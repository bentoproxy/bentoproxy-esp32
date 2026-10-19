//! Thin std::io wrapper over ESP-IDF's esp-tls.

use std::io::{Read, Write};

use anyhow::{anyhow, Result};
use log::info;

pub struct TlsStream {
    handle: *mut esp_idf_sys::esp_tls,
}

impl TlsStream {
    /// Open a TLS connection using the bundled root certificates.
    pub fn connect(host: &str, port: u16, timeout_ms: u32) -> Result<Self> {
        let mut config: esp_idf_sys::esp_tls_cfg_t = unsafe { std::mem::zeroed() };
        config.crt_bundle_attach = Some(esp_idf_sys::esp_crt_bundle_attach);
        config.timeout_ms = timeout_ms as i32;

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

        Ok(Self { handle })
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
            Err(tls_io_error("read"))
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
            Err(tls_io_error("write"))
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

// esp-tls reports "would block" through errno, as the socket layer does.
fn tls_io_error(op: &str) -> std::io::Error {
    let errno = unsafe { *esp_idf_sys::__errno() };
    if errno == esp_idf_sys::EWOULDBLOCK as i32 || errno == esp_idf_sys::EAGAIN as i32 {
        std::io::Error::new(std::io::ErrorKind::WouldBlock, "TLS would block")
    } else {
        std::io::Error::other(format!("TLS {op} error: errno {errno}"))
    }
}

fn io_error(message: &'static str) -> std::io::Error {
    std::io::Error::other(message)
}
