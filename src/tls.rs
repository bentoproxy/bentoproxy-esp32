//! Thin std::io wrapper over ESP-IDF's esp-tls.

use std::io::{Read, Write};

use anyhow::{anyhow, Result};
use log::info;

/// Cipher suites the C5 offers, best first, zero-terminated for mbedTLS.
///
/// ChaCha20-Poly1305 runs in plain software and is fast on a 32-bit core.
/// AES-GCM uses the AES engine, but the C5 has no GCM hardware, so its GHASH
/// half runs in software and each record pays the DMA setup: encryption was
/// the C5's throughput ceiling. AES-GCM stays as the fallback.
#[cfg(esp32c5)]
static CIPHERSUITES: [i32; 7] = [
    esp_idf_sys::MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 as i32,
    esp_idf_sys::MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 as i32,
    esp_idf_sys::MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 as i32,
    esp_idf_sys::MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as i32,
    esp_idf_sys::MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 as i32,
    esp_idf_sys::MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 as i32,
    0,
];

pub struct TlsStream {
    handle: *mut esp_idf_sys::esp_tls,
}

/// Which cipher suite the handshake settled on: it decides encryption cost.
fn log_ciphersuite(handle: *mut esp_idf_sys::esp_tls) {
    unsafe {
        let ssl = esp_idf_sys::esp_tls_get_ssl_context(handle) as *const esp_idf_sys::mbedtls_ssl_context;
        if ssl.is_null() {
            return;
        }
        let name = esp_idf_sys::mbedtls_ssl_get_ciphersuite(ssl);
        if !name.is_null() {
            info!("TLS cipher suite: {}", std::ffi::CStr::from_ptr(name).to_string_lossy());
        }
    }
}

impl TlsStream {
    /// Open a TLS connection using the bundled root certificates.
    pub fn connect(host: &str, port: u16, timeout_ms: u32) -> Result<Self> {
        let mut config: esp_idf_sys::esp_tls_cfg_t = unsafe { std::mem::zeroed() };
        config.crt_bundle_attach = Some(esp_idf_sys::esp_crt_bundle_attach);
        config.timeout_ms = timeout_ms as i32;
        #[cfg(esp32c5)]
        {
            config.ciphersuites_list = CIPHERSUITES.as_ptr();
        }

        let host_cstr = std::ffi::CString::new(host)?;
        let handle = unsafe { esp_idf_sys::esp_tls_init() };
        if handle.is_null() {
            return Err(anyhow!("esp_tls_init failed"));
        }

        info!("TLS connecting to {host}:{port}");
        let result = unsafe {
            esp_idf_sys::esp_tls_conn_new_sync(
                host_cstr.as_ptr(),
                host_cstr.as_bytes().len() as i32,
                port as i32,
                &config,
                handle,
            )
        };

        if result != 1 {
            unsafe { esp_idf_sys::esp_tls_conn_destroy(handle) };
            return Err(anyhow!("TLS handshake with {host}:{port} failed"));
        }

        log_ciphersuite(handle);
        Ok(Self { handle })
    }

    /// The socket's descriptor, for waiting on it with select().
    pub fn raw_fd(&self) -> Option<i32> {
        let mut fd: i32 = -1;
        let ok = unsafe { esp_idf_sys::esp_tls_get_conn_sockfd(self.handle, &mut fd) };
        (ok == esp_idf_sys::ESP_OK && fd >= 0).then_some(fd)
    }

    /// Plaintext already decrypted and buffered inside the TLS layer.
    ///
    /// select() cannot see it: once mbedTLS has pulled a record off the
    /// socket, the socket can be empty while data is ready. Anything waiting on
    /// the socket must check this first or it can block with input pending.
    pub fn pending(&self) -> usize {
        let n = unsafe { esp_idf_sys::esp_tls_get_bytes_avail(self.handle) };
        n.max(0) as usize
    }

    /// Switch the underlying socket between blocking and non-blocking.
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> std::io::Result<()> {
        unsafe {
            let mut sockfd: i32 = -1;
            if esp_idf_sys::esp_tls_get_conn_sockfd(self.handle, &mut sockfd) != esp_idf_sys::ESP_OK
                || sockfd < 0
            {
                return Err(io_error("failed to get TLS socket fd"));
            }

            let flags = esp_idf_sys::fcntl(sockfd, esp_idf_sys::F_GETFL as i32, 0);
            if flags < 0 {
                return Err(io_error("failed to read socket flags"));
            }

            let flags = if nonblocking {
                flags | esp_idf_sys::O_NONBLOCK as i32
            } else {
                flags & !(esp_idf_sys::O_NONBLOCK as i32)
            };

            if esp_idf_sys::fcntl(sockfd, esp_idf_sys::F_SETFL as i32, flags) < 0 {
                return Err(io_error("failed to set socket flags"));
            }

            Ok(())
        }
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe {
            esp_idf_sys::esp_tls_conn_read(self.handle, buf.as_mut_ptr() as *mut _, buf.len())
        };
        if n < 0 {
            Err(tls_io_error("read", n as i32))
        } else {
            Ok(n as usize)
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = unsafe {
            esp_idf_sys::esp_tls_conn_write(self.handle, buf.as_ptr() as *const _, buf.len())
        };
        if n < 0 {
            Err(tls_io_error("write", n as i32))
        } else {
            Ok(n as usize)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for TlsStream {
    fn drop(&mut self) {
        unsafe { esp_idf_sys::esp_tls_conn_destroy(self.handle) };
    }
}

/// Classify a negative esp-tls return by its code, not by errno.
///
/// Reading errno here was wrong: a failed TLS call can leave the code in its
/// return value while errno still holds an EAGAIN from some earlier socket
/// call. A real failure then looked like "try again", and the relay retried
/// it until a 20s deadline killed the session — every ~30s once the loop
/// polled fast enough to make stale values common.
fn tls_io_error(op: &str, code: i32) -> std::io::Error {
    match code {
        esp_idf_sys::ESP_TLS_ERR_SSL_WANT_READ | esp_idf_sys::ESP_TLS_ERR_SSL_WANT_WRITE => {
            std::io::Error::new(std::io::ErrorKind::WouldBlock, "TLS would block")
        }
        // TLS 1.3 servers send session tickets after the handshake. mbedTLS
        // reports one as its own code; it means "call again", not failure.
        esp_idf_sys::MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => {
            std::io::Error::new(std::io::ErrorKind::WouldBlock, "TLS session ticket received")
        }
        _ => std::io::Error::other(format!("TLS {op} failed: -0x{:04x}", code.unsigned_abs())),
    }
}

fn io_error(message: &'static str) -> std::io::Error {
    std::io::Error::other(message)
}
