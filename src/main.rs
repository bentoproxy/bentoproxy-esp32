//! BentoProxy ESP32 Node Firmware
//!
//! Connects to the BentoProxy orchestrator over a TLS WebSocket, authenticates,
//! and relays TCP streams on its behalf.
//!
//! Hardware: ESP32-S3 (or compatible)
//! Protocol: binary frames over WebSocket (see bentoproxy-protocol)

mod claim;
mod connect;
#[cfg(feature = "netdiag")]
mod diag;
mod netfilter;
mod profile;
mod provisioning;
mod settings;
mod tls;
mod wait;
mod ws;

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::fd::AsRawFd;
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
use esp_idf_svc::nvs::EspDefaultNvsPartition as NvsPartition;
use settings::Settings;
use tls::TlsStream;
use ws::WsConn;

/// Concurrent relayed streams. Each costs a socket and lwIP buffers, so the
/// ceiling is lwIP's socket table (CONFIG_LWIP_MAX_SOCKETS) minus the
/// orchestrator connection and room for DNS.
///
/// Deliberately higher than the capacity the orchestrator routes against: the
/// spare slots absorb bursts and leave room for an owner-triggered speed test,
/// which a node saturated with relayed traffic would otherwise refuse.
const MAX_CONCURRENT_STREAMS: usize = 12;
const RECONNECT_DELAY: Duration = Duration::from_secs(5);
const PING_INTERVAL: Duration = Duration::from_secs(20);
const WIFI_ATTEMPTS: u32 = 5;
/// How long setup stays open after the saved network could not be joined,
/// before rebooting to try that network again.
const PORTAL_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const TLS_TIMEOUT_MS: u32 = 30_000;
/// Longest an idle pass waits for socket activity. select() returns as soon
/// as any socket is readable, so this only bounds how late we notice events
/// that are not sockets: finished connects, and the ping timer.
const IDLE_WAIT: Duration = Duration::from_millis(20);
/// Per-stream read buffer, and so the largest relay frame.
///
/// Sized to fit one outgoing TLS record (16KB, see sdkconfig) after the
/// WebSocket header and protocol framing, so each frame is encrypted and
/// written once. Reads were filling an 8KB buffer every time, meaning data
/// arrived faster than one buffer per read.
const RELAY_BUFFER: usize = 16 * 1024 - 64;
/// Bytes a single stream may move per pass, so one busy download cannot
/// starve the other streams or delay the keep-alive ping.
const PER_STREAM_BUDGET: usize = 32 * 1024;
/// How often to log relayed throughput.
const THROUGHPUT_REPORT: Duration = Duration::from_secs(15);
/// Give up on a connection that has gone quiet.
///
/// The orchestrator pings well inside this, so silence means the link is dead
/// even though the socket still looks open — which is how a node disappears
/// and stays gone until someone reboots it.
const INBOUND_TIMEOUT: Duration = Duration::from_secs(120);

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

    // The last boot could not join its saved network: offer setup for a while
    // so the owner can choose a new one, keeping the node's claim.
    if Settings::take_portal_request(nvs.clone()).unwrap_or(false) {
        let unreachable = Settings::load(nvs.clone())
            .ok()
            .flatten()
            .map(|s| s.wifi_ssid);
        info!("saved WiFi was unreachable; opening setup for {}s", PORTAL_TIMEOUT.as_secs());
        match provisioning::run(peripherals.modem, sys_loop, nvs, Some(PORTAL_TIMEOUT), unreachable) {
            Ok(()) => restart("setup window closed"),
            Err(e) => restart(&format!("setup portal failed: {e:?}")),
        }
    }

    // Credentials come from NVS or from the build; a blank device opens its
    // own setup network instead.
    let settings = match Settings::load(nvs.clone()) {
        Ok(Some(settings)) => settings,
        Ok(None) => {
            info!("no settings stored; starting setup portal");
            match provisioning::run(peripherals.modem, sys_loop, nvs, None, None) {
                // Reboot so the normal path starts from a clean radio state
                // rather than switching the interface out from under lwIP.
                Ok(()) => restart("setup complete"),
                Err(e) => restart(&format!("setup portal failed: {e:?}")),
            }
        }
        Err(e) => restart(&format!("could not read settings: {e:?}")),
    };

    let nvs_for_claim = nvs.clone();
    let nvs_for_portal = nvs.clone();
    let mut wifi = match init_wifi(peripherals.modem, sys_loop.clone(), nvs, &settings) {
        Ok(wifi) => wifi,
        Err(e) => restart(&format!("WiFi init failed: {e:?}")),
    };

    if let Err(e) = connect_wifi(&mut wifi, &settings) {
        // Retrying forever helps nobody if the node has moved: its saved
        // network is simply not there. Reboot into setup instead, which times
        // out and retries the saved network, so an outage recovers by itself.
        warn!("could not join '{}': {e:?}", settings.wifi_ssid);
        if let Err(e) = Settings::request_portal(nvs_for_portal) {
            warn!("could not schedule setup: {e:?}");
        }
        restart("saved WiFi unreachable; opening setup on next boot");
    }

    #[cfg(feature = "netdiag")]
    diag::run();

    // Credentials arrive from a claim, not from the owner: the node announces
    // itself and waits for them to enter its setup code in the dashboard.
    let credentials = match (settings.device_id.clone(), settings.device_token.clone()) {
        (Some(device_id), Some(device_token)) => (device_id, device_token),
        _ => match obtain_credentials(&settings, nvs_for_claim) {
            Ok(credentials) => credentials,
            Err(e) => restart(&format!("could not obtain credentials: {e:?}")),
        },
    };

    info!("Device ID: {}", credentials.0);

    let mut led = PinDriver::output(peripherals.pins.gpio2).unwrap();
    led.set_low().ok();

    let connector = match Connector::spawn() {
        Ok(connector) => connector,
        Err(e) => restart(&format!("could not start the connect worker: {e:?}")),
    };

    loop {
        info!("Connecting to orchestrator: {}", settings.orchestrator_url);

        match run_session(&settings, &credentials, &connector, &mut led) {
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

                // IDF enables modem sleep by default: the radio dozes between
                // beacons and every packet waits for it to wake. Right for a
                // battery sensor, ruinous for a relay that is always moving
                // data and always on mains power.
                let result = unsafe {
                    esp_idf_sys::esp_wifi_set_ps(esp_idf_sys::wifi_ps_type_t_WIFI_PS_NONE)
                };
                if result == esp_idf_sys::ESP_OK {
                    info!("WiFi power saving disabled");
                } else {
                    warn!("could not disable WiFi power saving: {result}");
                }

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

/// Announce this node and wait for its owner to claim it, storing whatever
/// the orchestrator issues.
fn obtain_credentials(settings: &Settings, nvs: NvsPartition) -> Result<(String, String)> {
    let hw_id = claim::hardware_id()?;
    let setup_code = Settings::setup_code(nvs.clone())?;
    let api_base = claim::api_base_from_ws_url(&settings.orchestrator_url)?;

    let issued = claim::wait_for_claim(&api_base, &hw_id, &setup_code)?;
    Settings::save_credentials(nvs, &issued.device_id, &issued.device_token)?;

    Ok((issued.device_id, issued.device_token))
}

/// One orchestrator connection, from handshake until the link drops.
fn run_session(
    settings: &Settings,
    credentials: &(String, String),
    connector: &Connector,
    led: &mut Led,
) -> Result<()> {
    let (host, port, path) = parse_url(&settings.orchestrator_url)?;

    let mut tls = TlsStream::connect(host, port, TLS_TIMEOUT_MS)?;
    // Handshake and auth are a strict request/response exchange, so keep the
    // socket blocking until they are done.
    tls.set_nonblocking(false)?;

    let mut ws = WsConn::connect(tls, host, path)?;

    let (device_id, device_token) = credentials;
    info!("Authenticating as {device_id}");
    ws.send_frame(&Frame::auth(device_id, device_token))?;

    let response = read_frame_blocking(&mut ws)?;
    if response.frame_type != FrameType::Data || !response.flags.has_ack() {
        return Err(anyhow!("authentication rejected by orchestrator"));
    }
    info!("Authenticated");

    ws.get_mut().set_nonblocking(true)?;
    let tls_fd = ws.get_ref().raw_fd();
    ws.set_wait_fd(tls_fd);

    let mut streams: HashMap<u32, TcpStream> = HashMap::new();
    // On the heap, allocated once per session: as a stack array it can be
    // inlined into a frame that is live during the TLS handshake, and the two
    // together overflowed the main task's stack.
    let mut relay_buffer = vec![0u8; RELAY_BUFFER];
    // Streams the orchestrator opened that the worker has not finished yet.
    let mut pending: HashSet<u32> = HashSet::new();
    let mut last_ping = Instant::now();
    let mut last_report = Instant::now();
    let mut last_inbound = Instant::now();
    let mut reported_bytes = 0u64;

    loop {
        if last_ping.elapsed() >= PING_INTERVAL {
            debug!("Sending PING");
            ws.send_frame(&Frame::ping())?;
            last_ping = Instant::now();
        }

        let mut moved = 0usize;

        while let Some(frame) = ws.poll_frame()? {
            last_inbound = Instant::now();
            moved += handle_frame(frame, &mut ws, connector, &mut streams, &mut pending)?;
        }

        if last_inbound.elapsed() >= INBOUND_TIMEOUT {
            return Err(anyhow!(
                "nothing from the orchestrator in {}s; reconnecting",
                INBOUND_TIMEOUT.as_secs()
            ));
        }

        collect_connections(connector, &mut ws, &mut streams, &mut pending)?;
        moved += relay_to_orchestrator(&mut ws, &mut streams, &mut relay_buffer)?;

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
            info!("{}", profile::take_report(seconds));
            // Heap margin, so buffer tuning shows its cost before it shows a
            // crash. The minimum is the low-water mark since boot.
            info!(
                "heap: {} KB free, {} KB at lowest",
                unsafe { esp_idf_sys::esp_get_free_heap_size() } / 1024,
                unsafe { esp_idf_sys::esp_get_minimum_free_heap_size() } / 1024
            );
            reported_bytes = 0;
            last_report = Instant::now();
        }

        set_activity_led(led, !streams.is_empty());

        // Idle pass: wait for any socket to become readable rather than
        // sleeping a fixed interval. Busy passes loop straight back.
        if moved == 0 {
            profile::idle_sleep();

            // Plaintext already inside TLS is invisible to select(); with some
            // waiting, go straight round again.
            if ws.get_ref().pending() == 0 {
                let mut readable = wait::FdSet::new();
                if let Some(fd) = tls_fd {
                    readable.add(fd);
                }
                for stream in streams.values() {
                    readable.add(stream.as_raw_fd());
                }
                wait::wait(readable, wait::FdSet::new(), IDLE_WAIT);
            }
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
        thread::sleep(IDLE_WAIT);
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
    buffer: &mut [u8],
) -> Result<usize> {
    let mut finished = Vec::new();
    let mut total = 0usize;

    for (&stream_id, stream) in streams.iter_mut() {
        let mut from_stream = 0usize;

        while from_stream < PER_STREAM_BUDGET {
            let read_started = Instant::now();
            let result = stream.read(buffer);
            if let Ok(n) = result {
                profile::read_done(read_started, n);
            }
            match result {
                Ok(0) => {
                    debug!("stream {stream_id} EOF");
                    ws.send_frame(&Frame::close(stream_id))?;
                    finished.push(stream_id);
                    break;
                }
                Ok(n) => {
                    // Straight from the read buffer: no per-frame allocation.
                    ws.send_data(stream_id, &buffer[..n])?;
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
