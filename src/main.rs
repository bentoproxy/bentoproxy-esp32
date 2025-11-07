//! BentoProxy ESP32 Node Firmware
//!
//! This firmware connects to the BentoProxy orchestrator via WebSocket,
//! authenticates, and handles proxy streams by creating TCP connections.
//!
//! Hardware: ESP32-S3 (or compatible)
//! Network: WiFi
//! Protocol: WebSocket with binary frames (see bentoproxy-protocol)

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use std::io::{Read, Write};
use std::net::TcpStream;

use anyhow::{anyhow, Result};
use embedded_svc::wifi::{ClientConfiguration, Configuration};
use esp_idf_hal::prelude::Peripherals;
use esp_idf_hal::gpio::{PinDriver, Output};
use esp_idf_svc::{
    eventloop::EspSystemEventLoop,
    nvs::EspDefaultNvsPartition,
    wifi::{BlockingWifi, EspWifi},
};
use esp_idf_sys as _; // Required for esp-idf bindings
use log::{error, info, warn};

// Protocol imports
use bentoproxy_protocol::{Frame, FrameType};

const ORCHESTRATOR_URL: &str = env!("ORCHESTRATOR_URL");
const DEVICE_ID: &str = env!("DEVICE_ID");
const DEVICE_TOKEN: &str = env!("DEVICE_TOKEN");
const WIFI_SSID: &str = env!("WIFI_SSID");
const WIFI_PASSWORD: &str = env!("WIFI_PASSWORD");

const MAX_CONCURRENT_STREAMS: usize = 8;
const RECONNECT_DELAY_SECS: u64 = 5;

type StreamMap = Arc<Mutex<HashMap<u32, std::net::TcpStream>>>;
type LedPin = Arc<Mutex<PinDriver<'static, esp_idf_hal::gpio::Gpio2, Output>>>;

// TLS stream wrapper for esp-tls
struct TlsStream {
    handle: *mut esp_idf_sys::esp_tls,
}

impl TlsStream {
    unsafe fn new(handle: *mut esp_idf_sys::esp_tls) -> Self {
        Self { handle }
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> std::io::Result<()> {
        unsafe {
            // Get the socket file descriptor from the TLS handle
            let mut sockfd: i32 = -1;
            let result = esp_idf_sys::esp_tls_get_conn_sockfd(self.handle, &mut sockfd as *mut i32);

            if result != esp_idf_sys::ESP_OK || sockfd < 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to get socket fd"));
            }

            // Set O_NONBLOCK flag
            let mut flags = esp_idf_sys::fcntl(sockfd, esp_idf_sys::F_GETFL as i32, 0);
            if flags < 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to get socket flags"));
            }

            if nonblocking {
                flags |= esp_idf_sys::O_NONBLOCK as i32;
            } else {
                flags &= !(esp_idf_sys::O_NONBLOCK as i32);
            }

            let result = esp_idf_sys::fcntl(sockfd, esp_idf_sys::F_SETFL as i32, flags);
            if result < 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to set socket flags"));
            }

            Ok(())
        }
    }
}

impl std::io::Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe {
            esp_idf_sys::esp_tls_conn_read(
                self.handle,
                buf.as_mut_ptr() as *mut _,
                buf.len()
            )
        };
        if n < 0 {
            // esp_tls_conn_read returns -1 on error, check errno
            // ESP_TLS_ERR_SSL_WANT_READ/WRITE map to EWOULDBLOCK
            let errno = unsafe { *esp_idf_sys::__errno() };
            if errno == esp_idf_sys::EWOULDBLOCK as i32 || errno == esp_idf_sys::EAGAIN as i32 {
                Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "TLS would block"))
            } else {
                Err(std::io::Error::new(std::io::ErrorKind::Other, format!("TLS read error: errno {}", errno)))
            }
        } else {
            Ok(n as usize)
        }
    }
}

impl std::io::Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = unsafe {
            esp_idf_sys::esp_tls_conn_write(
                self.handle,
                buf.as_ptr() as *const _,
                buf.len()
            )
        };
        if n < 0 {
            // Check errno for WouldBlock (same as Read implementation)
            let errno = unsafe { *esp_idf_sys::__errno() };
            if errno == esp_idf_sys::EWOULDBLOCK as i32 || errno == esp_idf_sys::EAGAIN as i32 {
                Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "TLS would block on write"))
            } else {
                Err(std::io::Error::new(std::io::ErrorKind::Other, format!("TLS write error: errno {}", errno)))
            }
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
        unsafe {
            esp_idf_sys::esp_tls_conn_destroy(self.handle);
        }
    }
}

fn main() -> ! {
    // Initialize ESP-IDF services
    esp_idf_sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    info!("BentoProxy ESP32 Node starting...");
    info!("Device ID: {}", DEVICE_ID);

    let peripherals = Peripherals::take().unwrap();
    let sys_loop = EspSystemEventLoop::take().unwrap();
    let nvs = EspDefaultNvsPartition::take().unwrap();

    // Initialize WiFi
    info!("Initializing WiFi...");
    let mut wifi = match init_wifi(peripherals.modem, sys_loop.clone(), Some(nvs)) {
        Ok(wifi) => wifi,
        Err(e) => {
            error!("Failed to initialize WiFi: {:?}", e);
            panic!("WiFi init failed");
        }
    };

    // Try to connect to WiFi with retries
    let mut connected = false;
    for attempt in 1..=5 {
        info!("WiFi connection attempt {} of 5 to SSID: {}", attempt, WIFI_SSID);

        match wifi.connect() {
            Ok(()) => {
                info!("WiFi connect initiated, waiting for IP address...");
                match wifi.wait_netif_up() {
                    Ok(()) => {
                        info!("WiFi connected! IP: {:?}", wifi.wifi().sta_netif().get_ip_info());
                        connected = true;
                        break;
                    }
                    Err(e) => {
                        error!("Failed to get IP (attempt {}): {:?}", attempt, e);
                        if attempt < 5 {
                            warn!("Retrying in 3 seconds...");
                            thread::sleep(Duration::from_secs(3));
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to connect to WiFi (attempt {}): {:?}", attempt, e);
                if attempt < 5 {
                    warn!("Retrying in 3 seconds...");
                    thread::sleep(Duration::from_secs(3));
                }
            }
        }
    }

    if !connected {
        error!("Failed to connect to WiFi after 5 attempts");
        panic!("WiFi connection failed");
    }

    // Initialize LED on GPIO2
    info!("Initializing LED on GPIO2...");
    let led = Arc::new(Mutex::new(PinDriver::output(peripherals.pins.gpio2).unwrap()));
    // Start with LED off
    led.lock().unwrap().set_low().ok();
    info!("LED initialized");

    // Main loop: connect to orchestrator
    loop {
        info!("Connecting to orchestrator: {}", ORCHESTRATOR_URL);

        match connect_to_orchestrator(led.clone()) {
            Ok(()) => {
                info!("Orchestrator connection closed normally");
            }
            Err(e) => {
                error!("Orchestrator error: {:?}", e);
                warn!("Reconnecting in {} seconds...", RECONNECT_DELAY_SECS);
                thread::sleep(Duration::from_secs(RECONNECT_DELAY_SECS));
            }
        }
    }
}

/// Initialize WiFi with provided credentials
fn init_wifi(
    modem: impl esp_idf_hal::peripheral::Peripheral<P = esp_idf_hal::modem::Modem> + 'static,
    sys_loop: EspSystemEventLoop,
    nvs: Option<EspDefaultNvsPartition>,
) -> Result<BlockingWifi<EspWifi<'static>>> {
    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(modem, sys_loop.clone(), nvs)?,
        sys_loop,
    )?;

    wifi.start()?;

    info!("WiFi started, scanning for networks...");
    // Scan for networks to help with connection
    match wifi.scan() {
        Ok(aps) => {
            info!("Found {} access points:", aps.len());
            for ap in aps.iter().take(10) {
                info!("  - SSID: {:?}, Channel: {}, RSSI: {}, Auth: {:?}",
                    ap.ssid, ap.channel, ap.signal_strength, ap.auth_method);
            }
            // Check if our network is visible
            if let Some(target_ap) = aps.iter().find(|ap| ap.ssid == WIFI_SSID) {
                info!("Target network found! Channel: {}, RSSI: {}",
                    target_ap.channel, target_ap.signal_strength);
            } else {
                warn!("Target network '{}' not found in scan results!", WIFI_SSID);
            }
        }
        Err(e) => {
            warn!("WiFi scan failed: {:?}", e);
        }
    }

    let wifi_config = Configuration::Client(ClientConfiguration {
        ssid: WIFI_SSID.try_into().unwrap(),
        password: WIFI_PASSWORD.try_into().unwrap(),
        auth_method: embedded_svc::wifi::AuthMethod::WPA2Personal,
        ..Default::default()
    });

    wifi.set_configuration(&wifi_config)?;

    Ok(wifi)
}

/// Connect to orchestrator and handle frames
fn connect_to_orchestrator(led: LedPin) -> Result<()> {
    // Parse WebSocket URL
    let url = ORCHESTRATOR_URL
        .strip_prefix("wss://")
        .or_else(|| ORCHESTRATOR_URL.strip_prefix("ws://"))
        .ok_or_else(|| anyhow!("Invalid orchestrator URL"))?;

    let (host, path) = if let Some(idx) = url.find('/') {
        (&url[..idx], &url[idx..])
    } else {
        (url, "/")
    };

    let (host_name, port) = if let Some(idx) = host.find(':') {
        (&host[..idx], host[idx + 1..].parse::<u16>()?)
    } else {
        (host, if ORCHESTRATOR_URL.starts_with("wss://") { 443 } else { 80 })
    };

    info!("Connecting to {}:{}{}", host_name, port, path);

    // Create TLS connection using esp-tls
    let mut tls_config: esp_idf_sys::esp_tls_cfg_t = unsafe { std::mem::zeroed() };
    tls_config.crt_bundle_attach = Some(esp_idf_sys::esp_crt_bundle_attach);
    tls_config.timeout_ms = 30000;
    // Start in blocking mode for handshake, we'll switch to non-blocking later

    let host_cstr = std::ffi::CString::new(host_name)?;

    info!("Creating TLS connection to {}:{}...", host_name, port);
    let tls_handle = unsafe {
        esp_idf_sys::esp_tls_init()
    };

    if tls_handle.is_null() {
        return Err(anyhow!("Failed to initialize TLS"));
    }

    let result = unsafe {
        esp_idf_sys::esp_tls_conn_new_sync(
            host_cstr.as_ptr(),
            host_cstr.as_bytes().len() as i32,
            port as i32,
            &tls_config,
            tls_handle
        )
    };

    if result != 1 {
        unsafe { esp_idf_sys::esp_tls_conn_destroy(tls_handle); }
        return Err(anyhow!("TLS connection failed"));
    }

    info!("TLS connected, performing WebSocket handshake...");

    // Simple WebSocket handshake
    let handshake = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n",
        path, host_name
    );

    // Send handshake
    let sent = unsafe {
        esp_idf_sys::esp_tls_conn_write(
            tls_handle,
            handshake.as_ptr() as *const _,
            handshake.len()
        )
    };

    if sent < 0 {
        unsafe { esp_idf_sys::esp_tls_conn_destroy(tls_handle); }
        return Err(anyhow!("Failed to send WebSocket handshake"));
    }

    // Read handshake response
    let mut response = [0u8; 1024];
    let n = unsafe {
        esp_idf_sys::esp_tls_conn_read(
            tls_handle,
            response.as_mut_ptr() as *mut _,
            response.len()
        )
    };

    if n <= 0 {
        unsafe { esp_idf_sys::esp_tls_conn_destroy(tls_handle); }
        return Err(anyhow!("Failed to read WebSocket handshake response"));
    }

    let response_str = std::str::from_utf8(&response[..n as usize])?;

    if !response_str.contains("101 Switching Protocols") {
        unsafe { esp_idf_sys::esp_tls_conn_destroy(tls_handle); }
        return Err(anyhow!("WebSocket handshake failed: {}", response_str));
    }

    info!("WebSocket connected!");

    // Wrap in TlsStream
    let mut stream = unsafe { TlsStream::new(tls_handle) };

    // Send AUTH frame
    info!("Authenticating as device: {}", DEVICE_ID);
    let auth_frame = Frame::auth(DEVICE_ID, DEVICE_TOKEN);
    send_frame(&mut stream, &auth_frame)?;

    // Wait for AUTH ACK
    info!("Waiting for AUTH response...");
    match read_frame(&mut stream) {
        Ok(response_frame) => {
            info!("Received AUTH response: type={:?}, flags={:?}, stream_id={}, payload_len={}",
                response_frame.frame_type, response_frame.flags, response_frame.stream_id, response_frame.payload.len());

            if response_frame.frame_type != FrameType::Data || !response_frame.flags.has_ack() {
                return Err(anyhow!("AUTH failed: unexpected response type or missing ACK flag"));
            }

            info!("Authenticated successfully!");
        }
        Err(e) => {
            error!("Failed to read AUTH response: {:?}", e);
            return Err(anyhow!("AUTH response read error: {:?}", e));
        }
    }

    // Now switch to non-blocking mode for the main loop
    info!("Switching TLS socket to non-blocking mode");
    stream.set_nonblocking(true)?;

    // Stream map for managing active connections
    let streams: StreamMap = Arc::new(Mutex::new(HashMap::new()));

    // Track last ping time
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut last_ping_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    const PING_INTERVAL_SECS: u64 = 20; // Send PING every 20 seconds

    // Main message loop with non-blocking TCP relay
    loop {
        // Check if we need to send a PING
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if now - last_ping_time >= PING_INTERVAL_SECS {
            info!("Sending PING to orchestrator");
            let ping_frame = Frame::ping();
            send_frame(&mut stream, &ping_frame)?;
            last_ping_time = now;
        }

        // Try to read from WebSocket (non-blocking)
        match read_frame(&mut stream) {
            Ok(frame) => {
                info!("Received frame: {:?} stream_id={}", frame.frame_type, frame.stream_id);

                match frame.frame_type {
                    FrameType::Open => handle_open(&mut stream, frame, streams.clone(), led.clone())?,
                    FrameType::Data => handle_data(frame, streams.clone())?,
                    FrameType::Close => handle_close(frame.stream_id, streams.clone(), led.clone())?,
                    FrameType::Ping => {
                        info!("Received PING from orchestrator");
                        // No response needed - orchestrator just wants to know we're alive
                    }
                    _ => {
                        warn!("Unexpected frame type: {:?}", frame.frame_type);
                    }
                }
            }
            Err(e) => {
                // Check if it's a "would block" error (no data available)
                if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                    if io_err.kind() == std::io::ErrorKind::WouldBlock {
                        // No data available right now, continue to TCP relay and PING check
                    } else {
                        error!("Error reading frame: {:?}", e);
                        return Err(e);
                    }
                } else {
                    error!("Error reading frame: {:?}", e);
                    return Err(e);
                }
            }
        }

        // Poll all TCP streams for incoming data
        relay_tcp_to_ws(&mut stream, streams.clone())?;

        // Small delay to avoid busy loop
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Handle OPEN frame - create TCP connection to target
fn handle_open<S: Read + Write>(ws_stream: &mut S, frame: Frame, streams: StreamMap, led: LedPin) -> Result<()> {
    let (host, port) = frame.parse_open()?;
    let stream_id = frame.stream_id;

    info!("OPEN stream {} -> {}:{}", stream_id, host, port);

    // Create TCP connection to target
    // Note: TcpStream::connect() handles DNS resolution automatically
    let addr = format!("{}:{}", host, port);
    let tcp_stream = match TcpStream::connect(&addr) {
        Ok(stream) => stream,
        Err(e) => {
            error!("Failed to connect to {}:{}: {:?}", host, port, e);
            let err_frame = Frame::error(stream_id, 1);
            send_frame(ws_stream, &err_frame)?;
            return Ok(());
        }
    };

    match tcp_stream.set_nonblocking(true) {
        Ok(()) => {},
        Err(e) => {
            error!("Failed to set non-blocking mode: {:?}", e);
            let err_frame = Frame::error(stream_id, 1);
            send_frame(ws_stream, &err_frame)?;
            return Ok(());
        }
    }

    // Store stream
    {
        let mut map = streams.lock().unwrap();
        if map.len() >= MAX_CONCURRENT_STREAMS {
            error!("Too many concurrent streams");
            let err_frame = Frame::error(stream_id, 1);
            send_frame(ws_stream, &err_frame)?;
            return Ok(());
        }
        map.insert(stream_id, tcp_stream);
    }

    // Turn on LED - we have active connection(s)
    led.lock().unwrap().set_high().ok();

    // Send ACK
    let ack_frame = Frame::data_ack(stream_id);
    send_frame(ws_stream, &ack_frame)?;

    info!("Stream {} connected to {}:{}", stream_id, host, port);

    Ok(())
}

/// Handle DATA frame - write to TCP connection
fn handle_data(frame: Frame, streams: StreamMap) -> Result<()> {
    let stream_id = frame.stream_id;

    if frame.payload.is_empty() {
        // Empty DATA frame (likely ACK), ignore
        return Ok(());
    }

    let mut map = streams.lock().unwrap();
    if let Some(tcp_stream) = map.get_mut(&stream_id) {
        match tcp_stream.write_all(&frame.payload) {
            Ok(_) => {
                info!("Wrote {} bytes to stream {}", frame.payload.len(), stream_id);
                Ok(())
            }
            Err(e) => {
                error!("Failed to write to stream {}: {:?}", stream_id, e);
                map.remove(&stream_id);
                Err(e.into())
            }
        }
    } else {
        warn!("Stream {} not found", stream_id);
        Ok(())
    }
}

/// Handle CLOSE frame - close TCP connection
fn handle_close(stream_id: u32, streams: StreamMap, led: LedPin) -> Result<()> {
    info!("Closing stream {}", stream_id);
    let mut map = streams.lock().unwrap();
    map.remove(&stream_id);

    // Turn off LED if no more active connections
    if map.is_empty() {
        led.lock().unwrap().set_low().ok();
        info!("All streams closed, LED off");
    }

    Ok(())
}

/// Relay data from TCP stream to WebSocket
/// Poll all TCP streams and relay data to WebSocket
fn relay_tcp_to_ws<S: Write>(ws_stream: &mut S, streams: StreamMap) -> Result<()> {
    let mut buffer = [0u8; 4096];
    let mut streams_to_close = Vec::new();

    // Get list of active stream IDs
    let stream_ids: Vec<u32> = {
        let map = streams.lock().unwrap();
        map.keys().copied().collect()
    };

    // Poll each TCP stream for data
    for stream_id in stream_ids {
        let read_result = {
            let mut map = streams.lock().unwrap();
            if let Some(tcp_stream) = map.get_mut(&stream_id) {
                tcp_stream.read(&mut buffer)
            } else {
                continue;
            }
        };

        match read_result {
            Ok(0) => {
                // EOF - connection closed by remote
                info!("Stream {} EOF", stream_id);
                let close_frame = Frame::close(stream_id);
                send_frame(ws_stream, &close_frame)?;
                streams_to_close.push(stream_id);
            }
            Ok(n) => {
                // Data available - send to WebSocket
                info!("Stream {}: relaying {} bytes from TCP to WS", stream_id, n);
                let data_frame = Frame::data(stream_id, buffer[..n].to_vec().into());
                send_frame(ws_stream, &data_frame)?;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data available right now, that's fine
            }
            Err(e) => {
                error!("Error reading from stream {}: {:?}", stream_id, e);
                let err_frame = Frame::error(stream_id, 2);
                send_frame(ws_stream, &err_frame)?;
                streams_to_close.push(stream_id);
            }
        }
    }

    // Clean up closed streams
    for stream_id in streams_to_close {
        let mut map = streams.lock().unwrap();
        map.remove(&stream_id);
        info!("Removed closed stream {}", stream_id);
    }

    Ok(())
}

/// Write all data, retrying on WouldBlock
fn write_all_nonblocking<W: Write>(stream: &mut W, mut buf: &[u8]) -> Result<()> {
    while !buf.is_empty() {
        match stream.write(buf) {
            Ok(0) => return Err(anyhow!("Write returned 0 bytes")),
            Ok(n) => buf = &buf[n..],
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Wait a bit and retry
                thread::sleep(Duration::from_micros(100));
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Send a frame over WebSocket (simplified binary WebSocket framing)
fn send_frame<S: Write>(stream: &mut S, frame: &Frame) -> Result<()> {
    let payload = frame.to_bytes();
    let len = payload.len();

    // WebSocket binary frame header
    let mut header = vec![0x82]; // FIN + Binary opcode

    // Client MUST mask all frames sent to server (RFC 6455)
    let mask_bit = 0x80;

    if len < 126 {
        header.push((len as u8) | mask_bit);
    } else if len < 65536 {
        header.push(126 | mask_bit);
        header.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        header.push(127 | mask_bit);
        header.extend_from_slice(&(len as u64).to_be_bytes());
    }

    // Generate masking key (simple random-ish bytes)
    let mask_key = unsafe {
        let r = esp_idf_sys::esp_random();
        [
            (r & 0xFF) as u8,
            ((r >> 8) & 0xFF) as u8,
            ((r >> 16) & 0xFF) as u8,
            ((r >> 24) & 0xFF) as u8,
        ]
    };

    // Add masking key to header
    header.extend_from_slice(&mask_key);

    // Mask the payload (convert to Vec to allow mutation)
    let mut payload_vec = payload.to_vec();
    for (i, byte) in payload_vec.iter_mut().enumerate() {
        *byte ^= mask_key[i % 4];
    }

    info!("Sending WebSocket frame: len={}, masked=true", len);

    // Use non-blocking write helper
    write_all_nonblocking(stream, &header)?;
    write_all_nonblocking(stream, &payload_vec)?;
    stream.flush()?;

    Ok(())
}

/// Read a frame from WebSocket
fn read_frame<S: Read>(stream: &mut S) -> Result<Frame> {
    // Read WebSocket frame header
    let mut header = [0u8; 2];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) => {
            // Don't log WouldBlock as an error - it's expected in non-blocking mode
            if e.kind() != std::io::ErrorKind::WouldBlock {
                error!("Failed to read WebSocket header: {:?}", e);
            }
            return Err(e.into());
        }
    }

    let opcode = header[0] & 0x0F;
    let masked = (header[1] & 0x80) != 0;
    let mut payload_len = (header[1] & 0x7F) as usize;

    info!("WebSocket frame: opcode={}, masked={}, payload_len={}", opcode, masked, payload_len);

    // Extended payload length
    if payload_len == 126 {
        let mut len_bytes = [0u8; 2];
        stream.read_exact(&mut len_bytes)?;
        payload_len = u16::from_be_bytes(len_bytes) as usize;
        info!("Extended payload length (16-bit): {}", payload_len);
    } else if payload_len == 127 {
        let mut len_bytes = [0u8; 8];
        stream.read_exact(&mut len_bytes)?;
        payload_len = u64::from_be_bytes(len_bytes) as usize;
        info!("Extended payload length (64-bit): {}", payload_len);
    }

    // Masking key (if masked)
    let mask = if masked {
        let mut mask_bytes = [0u8; 4];
        stream.read_exact(&mut mask_bytes)?;
        Some(mask_bytes)
    } else {
        None
    };

    // Read payload
    info!("Reading {} bytes of payload...", payload_len);
    let mut payload = vec![0u8; payload_len];
    match stream.read_exact(&mut payload) {
        Ok(()) => {
            info!("Successfully read payload");
        }
        Err(e) => {
            error!("Failed to read payload: {:?}", e);
            return Err(e.into());
        }
    }

    // Unmask if needed
    if let Some(mask_key) = mask {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask_key[i % 4];
        }
    }

    // Parse BentoProxy frame
    Frame::from_bytes(payload.into()).map_err(|e| anyhow!("Frame parse error: {:?}", e))
}
