//! BentoProxy ESP32 Node Firmware
//!
//! Connects to the BentoProxy orchestrator over a TLS WebSocket, authenticates,
//! and relays TCP streams on its behalf.
//!
//! Hardware: ESP32-S3 (or compatible)
//! Protocol: binary frames over WebSocket (see bentoproxy-protocol)

mod connect;
mod netfilter;
mod provisioning;
mod settings;
mod tls;
mod ws;

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use embedded_svc::wifi::{ClientConfiguration, Configuration};
use esp_idf_hal::gpio::{Output, PinDriver};
use esp_idf_hal::prelude::Peripherals;
use esp_idf_svc::{
    eventloop::EspSystemEventLoop,
    nvs::EspDefaultNvsPartition,
    wifi::{BlockingWifi, EspWifi},
};
use esp_idf_sys as _; // Required for esp-idf bindings

// Emits the esp_app_desc structure the bootloader and espflash expect in an
// IDF application image.
esp_idf_sys::esp_app_desc!();
use log::{debug, error, info, warn};

use bentoproxy_protocol::{Frame, FrameType};
use connect::{Connector, Outcome};
use settings::Settings;
use tls::TlsStream;
use ws::WsConn;

/// Concurrent relayed streams. Each one costs a socket and lwIP buffers, so
/// this is bounded by RAM rather than by policy.
const MAX_CONCURRENT_STREAMS: usize = 8;
const RECONNECT_DELAY: Duration = Duration::from_secs(5);
const PING_INTERVAL: Duration = Duration::from_secs(20);
const WIFI_ATTEMPTS: u32 = 5;
const TLS_TIMEOUT_MS: u32 = 30_000;
/// Backoff when there is nothing to do. Only applied on an idle pass: a busy
/// pass loops straight back, because sleeping between every read used to cap a
/// stream at one buffer per interval (~400 KB/s) regardless of link speed.
const IDLE_BACKOFF: Duration = Duration::from_millis(10);
/// Per-stream read buffer. A multiple of lwIP's 1440-byte MSS.
const RELAY_BUFFER: usize = 8192;
/// Bytes a single stream may move per pass, so one busy download cannot
/// starve the other streams or delay the keep-alive ping.
const PER_STREAM_BUDGET: usize = 32 * 1024;
/// How often to log relayed throughput.
const THROUGHPUT_REPORT: Duration = Duration::from_secs(60);

type Led = PinDriver<'static, esp_idf_hal::gpio::Gpio2, Output>;

fn main() -> ! {
    esp_idf_sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    info!("BentoProxy ESP32 node starting...");

    let peripherals = Peripherals::take().unwrap();
    let sys_loop = EspSystemEventLoop::take().unwrap();
    let nvs = EspDefaultNvsPartition::take().unwrap();

    // Holding BOOT at power-on returns the node to setup, for resale or a
    // changed router.
    if boot_button_held(peripherals.pins.gpio0) {
        match Settings::erase(nvs.clone()) {
            Ok(()) => restart("factory reset requested"),
            Err(e) => restart(&format!("factory reset failed: {e:?}")),
        }
    }

    // Credentials come from NVS or from the build; a blank device opens its
    // own setup network instead.
    let settings = match Settings::load(nvs.clone()) {
        Ok(Some(settings)) => settings,
        Ok(None) => {
            info!("no settings stored; starting setup portal");
            match provisioning::run(peripherals.modem, sys_loop, nvs) {
                // Reboot so the normal path starts from a clean radio state
                // rather than switching the interface out from under lwIP.
                Ok(()) => restart("setup complete"),
                Err(e) => restart(&format!("setup portal failed: {e:?}")),
            }
        }
        Err(e) => restart(&format!("could not read settings: {e:?}")),
    };

    info!("Device ID: {}", settings.device_id);

    let mut wifi = match init_wifi(peripherals.modem, sys_loop.clone(), nvs, &settings) {
        Ok(wifi) => wifi,
        Err(e) => restart(&format!("WiFi init failed: {e:?}")),
    };

    if let Err(e) = connect_wifi(&mut wifi, &settings) {
        // A reboot retries from scratch, including a fresh DHCP lease, which
        // beats sitting in a panicked state until someone power-cycles it.
        restart(&format!("WiFi connection failed: {e:?}"));
    }

    let mut led = PinDriver::output(peripherals.pins.gpio2).unwrap();
    led.set_low().ok();

    let connector = match Connector::spawn() {
        Ok(connector) => connector,
        Err(e) => restart(&format!("could not start the connect worker: {e:?}")),
    };

    loop {
        info!("Connecting to orchestrator: {}", settings.orchestrator_url);

        match run_session(&settings, &connector, &mut led) {
            Ok(()) => info!("Orchestrator connection closed"),
            Err(e) => error!("Session ended: {e:?}"),
        }

        led.set_low().ok();
        warn!("Reconnecting in {}s...", RECONNECT_DELAY.as_secs());
        thread::sleep(RECONNECT_DELAY);
    }
}

/// Is the BOOT button held down? Checked once at startup, so a later press
/// cannot wipe a working node by accident.
fn boot_button_held(pin: esp_idf_hal::gpio::Gpio0) -> bool {
    const HOLD: Duration = Duration::from_secs(3);

    let Ok(button) = esp_idf_hal::gpio::PinDriver::input(pin) else {
        return false;
    };

    // The BOOT button pulls the pin low.
    if button.is_high() {
        return false;
    }

    info!("BOOT held; keep holding {}s for a factory reset", HOLD.as_secs());
    let deadline = Instant::now() + HOLD;
    while Instant::now() < deadline {
        if button.is_high() {
            info!("BOOT released; continuing normal startup");
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }

    true
}

/// Log the reason and reboot. Returns never, so callers can use it in place
/// of a panic that would leave the node dead until it is unplugged.
fn restart(reason: &str) -> ! {
    error!("{reason}");
    error!("Restarting in 5s...");
    thread::sleep(Duration::from_secs(5));
    unsafe { esp_idf_sys::esp_restart() }
}

fn init_wifi(
    modem: impl esp_idf_hal::peripheral::Peripheral<P = esp_idf_hal::modem::Modem> + 'static,
    sys_loop: EspSystemEventLoop,
    nvs: EspDefaultNvsPartition,
    settings: &Settings,
) -> Result<BlockingWifi<EspWifi<'static>>> {
    let mut wifi = BlockingWifi::wrap(EspWifi::new(modem, sys_loop.clone(), Some(nvs))?, sys_loop)?;
    wifi.start()?;

    // A scan makes "wrong SSID" and "out of range" distinguishable in the log.
    match wifi.scan() {
        Ok(aps) => match aps.iter().find(|ap| ap.ssid.as_str() == settings.wifi_ssid) {
            Some(ap) => info!(
                "Network '{}' found: channel {}, RSSI {}",
                settings.wifi_ssid, ap.channel, ap.signal_strength
            ),
            None => warn!(
                "Network '{}' not visible; {} other networks in range",
                settings.wifi_ssid,
                aps.len()
            ),
        },
        Err(e) => warn!("WiFi scan failed: {e:?}"),
    }

    wifi.set_configuration(&Configuration::Client(ClientConfiguration {
        ssid: settings
            .wifi_ssid
            .as_str()
            .try_into()
            .map_err(|_| anyhow!("SSID is too long"))?,
        password: settings
            .wifi_password
            .as_str()
            .try_into()
            .map_err(|_| anyhow!("WiFi password is too long"))?,
        auth_method: if settings.wifi_password.is_empty() {
            embedded_svc::wifi::AuthMethod::None
        } else {
            embedded_svc::wifi::AuthMethod::WPA2Personal
        },
        ..Default::default()
    }))?;

    Ok(wifi)
}

fn connect_wifi(wifi: &mut BlockingWifi<EspWifi<'static>>, settings: &Settings) -> Result<()> {
    for attempt in 1..=WIFI_ATTEMPTS {
        info!("WiFi attempt {attempt}/{WIFI_ATTEMPTS} to '{}'", settings.wifi_ssid);

        match wifi.connect().and_then(|()| wifi.wait_netif_up()) {
            Ok(()) => {
                info!("WiFi connected: {:?}", wifi.wifi().sta_netif().get_ip_info());
                return Ok(());
            }
            Err(e) => {
                warn!("WiFi attempt {attempt} failed: {e:?}");
                thread::sleep(Duration::from_secs(3));
            }
        }
    }

    Err(anyhow!("no WiFi after {WIFI_ATTEMPTS} attempts"))
}

/// One orchestrator connection, from handshake until the link drops.
fn run_session(settings: &Settings, connector: &Connector, led: &mut Led) -> Result<()> {
    let (host, port, path) = parse_url(&settings.orchestrator_url)?;

    let mut tls = TlsStream::connect(host, port, TLS_TIMEOUT_MS)?;
    // Handshake and auth are a strict request/response exchange, so keep the
    // socket blocking until they are done.
    tls.set_nonblocking(false)?;

    let mut ws = WsConn::connect(tls, host, path)?;

    info!("Authenticating as {}", settings.device_id);
    ws.send_frame(&Frame::auth(&settings.device_id, &settings.device_token))?;

    let response = read_frame_blocking(&mut ws)?;
    if response.frame_type != FrameType::Data || !response.flags.has_ack() {
        return Err(anyhow!("authentication rejected by orchestrator"));
    }
    info!("Authenticated");

    ws.get_mut().set_nonblocking(true)?;

    let mut streams: HashMap<u32, TcpStream> = HashMap::new();
    // Streams the orchestrator opened that the worker has not finished yet.
    let mut pending: HashSet<u32> = HashSet::new();
    let mut last_ping = Instant::now();
    let mut last_report = Instant::now();
    let mut reported_bytes = 0u64;

    loop {
        if last_ping.elapsed() >= PING_INTERVAL {
            debug!("Sending PING");
            ws.send_frame(&Frame::ping())?;
            last_ping = Instant::now();
        }

        let mut moved = 0usize;

        while let Some(frame) = ws.poll_frame()? {
            moved += handle_frame(frame, &mut ws, connector, &mut streams, &mut pending)?;
        }

        collect_connections(connector, &mut ws, &mut streams, &mut pending)?;
        moved += relay_to_orchestrator(&mut ws, &mut streams)?;

        reported_bytes += moved as u64;
        if last_report.elapsed() >= THROUGHPUT_REPORT {
            let seconds = last_report.elapsed().as_secs_f32();
            info!(
                "relayed {:.1} KB in {:.0}s ({:.1} KB/s) across {} streams",
                reported_bytes as f32 / 1024.0,
                seconds,
                reported_bytes as f32 / 1024.0 / seconds,
                streams.len()
            );
            reported_bytes = 0;
            last_report = Instant::now();
        }

        set_activity_led(led, !streams.is_empty());

        // Yield only when idle, so bulk transfers run at link speed.
        if moved == 0 {
            thread::sleep(IDLE_BACKOFF);
        }
    }
}

/// Wait for a single frame, for the strictly sequential auth exchange.
fn read_frame_blocking<S: Read + Write>(ws: &mut WsConn<S>) -> Result<Frame> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(frame) = ws.poll_frame()? {
            return Ok(frame);
        }
        if Instant::now() > deadline {
            return Err(anyhow!("timed out waiting for the orchestrator's reply"));
        }
        thread::sleep(IDLE_BACKOFF);
    }
}

/// Act on one orchestrator frame, returning the bytes written to a target.
fn handle_frame<S: Read + Write>(
    frame: Frame,
    ws: &mut WsConn<S>,
    connector: &Connector,
    streams: &mut HashMap<u32, TcpStream>,
    pending: &mut HashSet<u32>,
) -> Result<usize> {
    let stream_id = frame.stream_id;

    match frame.frame_type {
        FrameType::Open => {
            let (host, port) = frame.parse_open()?;
            info!("OPEN stream {stream_id} -> {host}:{port}");

            if streams.len() + pending.len() >= MAX_CONCURRENT_STREAMS {
                warn!("refusing stream {stream_id}: at the {MAX_CONCURRENT_STREAMS}-stream limit");
                ws.send_frame(&Frame::error(stream_id, 1))?;
                return Ok(0);
            }

            // Resolve and connect happen on the worker thread; the ACK follows
            // when it reports back.
            if connector.request(stream_id, host.to_string(), port) {
                pending.insert(stream_id);
            } else {
                error!("connect worker is gone");
                ws.send_frame(&Frame::error(stream_id, 1))?;
            }
        }

        FrameType::Data => {
            if frame.payload.is_empty() {
                return Ok(0); // Empty DATA is an ACK.
            }
            match streams.get_mut(&stream_id) {
                Some(stream) => {
                    if let Err(e) = write_all_nonblocking(stream, &frame.payload) {
                        error!("stream {stream_id} write failed: {e}");
                        streams.remove(&stream_id);
                        ws.send_frame(&Frame::close(stream_id))?;
                    } else {
                        debug!("wrote {} bytes to stream {stream_id}", frame.payload.len());
                        return Ok(frame.payload.len());
                    }
                }
                // Data for a stream still connecting has nowhere to go; the
                // orchestrator resends after the ACK.
                None if pending.contains(&stream_id) => {
                    warn!("dropping data for stream {stream_id}, still connecting")
                }
                None => warn!("data for unknown stream {stream_id}"),
            }
        }

        FrameType::Close => {
            info!("CLOSE stream {stream_id}");
            streams.remove(&stream_id);
            // If it is still connecting, forget it so the socket is dropped
            // when the worker hands it over.
            pending.remove(&stream_id);
        }

        FrameType::Ping => debug!("PING from orchestrator"),

        other => warn!("unexpected frame type: {other:?}"),
    }

    Ok(0)
}

/// Adopt sockets the worker finished, and answer the orchestrator.
fn collect_connections<S: Read + Write>(
    connector: &Connector,
    ws: &mut WsConn<S>,
    streams: &mut HashMap<u32, TcpStream>,
    pending: &mut HashSet<u32>,
) -> Result<()> {
    for outcome in connector.poll() {
        match outcome {
            Outcome::Connected { stream_id, stream } => {
                if !pending.remove(&stream_id) {
                    // Closed while connecting: dropping the socket closes it.
                    debug!("discarding stream {stream_id}, closed while connecting");
                    continue;
                }
                streams.insert(stream_id, stream);
                ws.send_frame(&Frame::data_ack(stream_id))?;
            }
            Outcome::Failed { stream_id } => {
                if pending.remove(&stream_id) {
                    ws.send_frame(&Frame::error(stream_id, 1))?;
                }
            }
        }
    }

    Ok(())
}

/// Forward whatever the targets sent back, returning the bytes relayed.
///
/// Each stream is drained until it blocks or hits its budget, rather than one
/// buffer per pass: a single read per loop iteration made throughput a
/// function of the loop interval instead of the link.
fn relay_to_orchestrator<S: Read + Write>(
    ws: &mut WsConn<S>,
    streams: &mut HashMap<u32, TcpStream>,
) -> Result<usize> {
    let mut buffer = [0u8; RELAY_BUFFER];
    let mut finished = Vec::new();
    let mut total = 0usize;

    for (&stream_id, stream) in streams.iter_mut() {
        let mut from_stream = 0usize;

        while from_stream < PER_STREAM_BUDGET {
            match stream.read(&mut buffer) {
                Ok(0) => {
                    debug!("stream {stream_id} EOF");
                    ws.send_frame(&Frame::close(stream_id))?;
                    finished.push(stream_id);
                    break;
                }
                Ok(n) => {
                    ws.send_frame(&Frame::data(stream_id, buffer[..n].to_vec().into()))?;
                    from_stream += n;
                    if n < buffer.len() {
                        break; // Drained for now.
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    error!("stream {stream_id} read failed: {e}");
                    ws.send_frame(&Frame::error(stream_id, 2))?;
                    finished.push(stream_id);
                    break;
                }
            }
        }

        total += from_stream;
    }

    for stream_id in finished {
        streams.remove(&stream_id);
    }

    Ok(total)
}

fn set_activity_led(led: &mut Led, active: bool) {
    let _ = if active { led.set_high() } else { led.set_low() };
}

fn write_all_nonblocking<W: Write>(stream: &mut W, mut buf: &[u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        match stream.write(buf) {
            Ok(0) => return Err(std::io::Error::other("write returned 0 bytes")),
            Ok(n) => buf = &buf[n..],
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_micros(500));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Split a ws:// or wss:// URL into host, port and path.
fn parse_url(url: &str) -> Result<(&str, u16, &str)> {
    let (rest, default_port) = match url.strip_prefix("wss://") {
        Some(rest) => (rest, 443),
        None => (
            url.strip_prefix("ws://")
                .ok_or_else(|| anyhow!("orchestrator URL must start with ws:// or wss://"))?,
            80,
        ),
    };

    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };

    match authority.rsplit_once(':') {
        Some((host, port)) => Ok((host, port.parse()?, path)),
        None => Ok((authority, default_port, path)),
    }
}
