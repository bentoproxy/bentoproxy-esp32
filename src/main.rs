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
mod ota;
mod profile;
mod provisioning;
mod settings;
mod status_led;
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
use esp_idf_hal::gpio::{AnyIOPin, PinDriver, Pull};
use esp_idf_hal::peripherals::Peripherals;
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

use bentoproxy_protocol::{Capabilities, Frame, FrameType, NodeKind};
use esp_idf_hal::task::watchdog::{config::Config as WatchdogConfig, TWDTDriver};
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
///
/// The S3 is bounded by its RAM; the XIAO C5 has 8MB of PSRAM, so there the
/// socket table is the limit (24 sockets, see sdkconfig.c5).
#[cfg(not(esp32c5))]
const MAX_CONCURRENT_STREAMS: usize = 12;
#[cfg(esp32c5)]
const MAX_CONCURRENT_STREAMS: usize = 20;
/// Streams the orchestrator should route here at once, declared at auth.
/// Below MAX_CONCURRENT_STREAMS on purpose: the spare slots absorb bursts and
/// keep room for an owner-triggered speed test on a busy node.
#[cfg(not(esp32c5))]
const ROUTABLE_STREAMS: u16 = 8;
#[cfg(esp32c5)]
const ROUTABLE_STREAMS: u16 = 16;
/// A relay loop that stops feeding the watchdog this long reboots the node.
/// Well above the longest legitimate stall in the loop (the 20s write
/// deadline), so it only fires on a real hang.
const WATCHDOG_TIMEOUT: Duration = Duration::from_secs(45);
const RECONNECT_DELAY: Duration = Duration::from_secs(5);
/// How often a running node looks for a firmware update. It also checks at
/// every boot. The check ends the relay session briefly: downloading needs a
/// second TLS connection, and the heap cannot hold two under load.
const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);
const PING_INTERVAL: Duration = Duration::from_secs(20);
const WIFI_ATTEMPTS: u32 = 5;
const WIFI_ATTEMPTS_NOT_VISIBLE: u32 = 2;
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
/// A read can never return more than one TCP receive window (5760 bytes, see
/// sdkconfig), so 16KB here was two-thirds empty; under 12 streams every read
/// measured exactly 5760. Sized to fit one 8KB outgoing TLS record after the
/// WebSocket and protocol headers, so each frame is still encrypted and
/// written once, and the memory goes back to the heap, which is the scarce
/// resource.
const RELAY_BUFFER: usize = 8 * 1024 - 64;
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

/// Whether this boot has confirmed its image yet (see ota::confirm_running).
static IMAGE_CONFIRMED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);


fn main() -> ! {
    esp_idf_sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    info!("BentoProxy ESP32 node starting...");

    let peripherals = Peripherals::take().unwrap();
    let sys_loop = EspSystemEventLoop::take().unwrap();
    let nvs = EspDefaultNvsPartition::take().unwrap();

    // Holding BOOT for 10s while running returns the node to setup, for
    // resale or a changed router.
    // BOOT is GPIO0 on the S3 and GPIO28 on any C5 (its download strap).
    #[cfg(not(esp32c5))]
    let boot_button = peripherals.pins.gpio0.degrade_input_output();
    #[cfg(esp32c5)]
    let boot_button = peripherals.pins.gpio28.degrade_input_output();
    watch_reset_button(boot_button, nvs.clone());

    // Started first, so every state from here on shows (see status_led).
    #[cfg(not(esp32c5))]
    let led = status_led::Led {
        pin: PinDriver::output(peripherals.pins.gpio2).unwrap(),
        lit_when_high: true,
    };
    // The XIAO ESP32-C5's yellow user LED lights when its pin is low.
    #[cfg(esp32c5)]
    let led = status_led::Led {
        pin: PinDriver::output(peripherals.pins.gpio27).unwrap(),
        lit_when_high: false,
    };
    status_led::start(led);

    #[cfg(feature = "portal-test")]
    let _ = Settings::request_portal(nvs.clone());

    // The last boot could not join its saved network: offer setup for a while
    // so the owner can choose a new one, keeping the node's claim.
    if Settings::take_portal_request(nvs.clone()).unwrap_or(false) {
        let unreachable = Settings::load(nvs.clone())
            .ok()
            .flatten()
            .map(|s| s.wifi_ssid);
        info!("saved WiFi was unreachable; opening setup for {}s", PORTAL_TIMEOUT.as_secs());
        status_led::set(status_led::State::Setup);
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
            status_led::set(status_led::State::Setup);
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
    let nvs_for_ota = nvs.clone();
    status_led::set(status_led::State::Connecting);
    let (mut wifi, network_visible) = match init_wifi(peripherals.modem, sys_loop.clone(), nvs, &settings) {
        Ok(result) => result,
        Err(e) => restart(&format!("WiFi init failed: {e:?}")),
    };

    // A network the scan cannot see is most likely gone — the node moved —
    // so give up quickly and open setup, rather than spending ~100s on
    // retries. Two attempts, not one, in case it is hidden or just missed.
    let attempts = if network_visible { WIFI_ATTEMPTS } else { WIFI_ATTEMPTS_NOT_VISIBLE };
    if let Err(e) = connect_wifi(&mut wifi, &settings, attempts) {
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
    info!("Firmware version: {}", ota::firmware_version());

    // Before relaying anything: a node that is already out of date should not
    // spend a session on the old firmware, and the heap is at its emptiest.
    let api_base = claim::api_base_from_ws_url(&settings.orchestrator_url).unwrap_or_default();
    ota::reconcile_after_boot(nvs_for_ota.clone());
    check_for_update(&api_base, nvs_for_ota.clone());
    let mut last_update_check = Instant::now();


    // Two different wedges have left nodes connected but dead until someone
    // power-cycled them. Whatever the next one is, the watchdog turns it into
    // a reboot, and the node reconnects on its own.
    let mut watchdog_config = WatchdogConfig::new();
    watchdog_config.duration = WATCHDOG_TIMEOUT;
    watchdog_config.panic_on_trigger = true;
    let mut watchdog = match TWDTDriver::new(peripherals.twdt, &watchdog_config) {
        Ok(watchdog) => watchdog,
        Err(e) => restart(&format!("could not start the watchdog: {e:?}")),
    };

    let connector = match Connector::spawn() {
        Ok(connector) => connector,
        Err(e) => restart(&format!("could not start the connect worker: {e:?}")),
    };

    loop {
        info!("Connecting to orchestrator: {}", settings.orchestrator_url);
        status_led::set(status_led::State::Connecting);

        let session_deadline = last_update_check + UPDATE_CHECK_INTERVAL;
        match run_session(
            &settings,
            &credentials,
            &connector,
            &mut watchdog,
            session_deadline,
            nvs_for_ota.clone(),
        ) {
            Ok(()) => info!("Orchestrator connection closed"),
            Err(e) => error!("Session ended: {e:?}"),
        }

        if last_update_check.elapsed() >= UPDATE_CHECK_INTERVAL {
            check_for_update(&api_base, nvs_for_ota.clone());
            last_update_check = Instant::now();
        }

        warn!("Reconnecting in {}s...", RECONNECT_DELAY.as_secs());
        thread::sleep(RECONNECT_DELAY);
    }
}

/// Watch the BOOT button for a factory reset: held for 10s at any time.
///
/// Not at power-on: BOOT is the chip's strapping pin, and holding it while
/// powering up starts the ROM's flashing mode instead of this firmware. Ten
/// seconds is long enough that a brush against the button wipes nothing.
fn watch_reset_button(pin: AnyIOPin<'static>, nvs: EspDefaultNvsPartition) {
    const HOLD: Duration = Duration::from_secs(10);
    const POLL: Duration = Duration::from_millis(100);

    // Pulled up so an unpressed button reads high on boards without their
    // own pull-up resistor.
    let Ok(button) = PinDriver::input(pin, Pull::Up) else {
        warn!("BOOT button unavailable; factory reset disabled");
        return;
    };

    let spawned = thread::Builder::new()
        .name("reset-button".into())
        .stack_size(4096)
        .spawn(move || {
            let mut pressed_since: Option<Instant> = None;
            loop {
                // The BOOT button pulls the pin low.
                if button.is_low() {
                    let since = *pressed_since.get_or_insert_with(|| {
                        info!("BOOT pressed; hold {}s for a factory reset", HOLD.as_secs());
                        Instant::now()
                    });
                    if since.elapsed() >= HOLD {
                        match Settings::erase(nvs.clone()) {
                            Ok(()) => restart("factory reset requested"),
                            Err(e) => restart(&format!("factory reset failed: {e:?}")),
                        }
                    }
                } else if pressed_since.take().is_some() {
                    info!("BOOT released early; no reset");
                }
                thread::sleep(POLL);
            }
        });
    if let Err(e) = spawned {
        warn!("could not watch the BOOT button: {e:?}");
    }
}

/// Install a newer verified release if there is one, rebooting into it.
/// Failures are logged and the node carries on with what it runs: a broken
/// update server must never take nodes offline.
fn check_for_update(api_base: &str, nvs: NvsPartition) {
    if api_base.is_empty() {
        return;
    }
    match ota::check_and_install(api_base, nvs) {
        Ok(ota::Outcome::Installed { version }) => {
            restart(&format!("rebooting into firmware {version}"));
        }
        Ok(ota::Outcome::UpToDate) => {}
        Err(e) => warn!("update check failed: {e:?}"),
    }
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
    modem: impl esp_idf_hal::modem::WifiModemPeripheral + 'static,
    sys_loop: EspSystemEventLoop,
    nvs: EspDefaultNvsPartition,
    settings: &Settings,
) -> Result<(BlockingWifi<EspWifi<'static>>, bool)> {
    let mut wifi = BlockingWifi::wrap(EspWifi::new(modem, sys_loop.clone(), Some(nvs))?, sys_loop)?;
    wifi.start()?;

    // A scan makes "wrong SSID" and "out of range" distinguishable in the log,
    // and tells the caller whether retrying is worth it.
    let visible = match wifi.scan() {
        Ok(aps) => match aps.iter().find(|ap| ap.ssid.as_str() == settings.wifi_ssid) {
            Some(ap) => {
                info!(
                    "Network '{}' found: channel {}, RSSI {}",
                    settings.wifi_ssid, ap.channel, ap.signal_strength
                );
                true
            }
            None => {
                warn!(
                    "Network '{}' not visible; {} other networks in range",
                    settings.wifi_ssid,
                    aps.len()
                );
                false
            }
        },
        // A failed scan says nothing either way: assume visible.
        Err(e) => {
            warn!("WiFi scan failed: {e:?}");
            true
        }
    };

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

    Ok((wifi, visible))
}

fn connect_wifi(
    wifi: &mut BlockingWifi<EspWifi<'static>>,
    settings: &Settings,
    attempts: u32,
) -> Result<()> {
    for attempt in 1..=attempts {
        info!("WiFi attempt {attempt}/{attempts} to '{}'", settings.wifi_ssid);

        match wifi.connect().and_then(|()| wifi.wait_netif_up()) {
            Ok(()) => {
                info!("WiFi connected: {:?}", wifi.wifi().sta_netif().get_ip_info());

                log_link_quality();

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

    Err(anyhow!("no WiFi after {attempts} attempts"))
}

/// Announce this node and wait for its owner to claim it, storing whatever
/// the orchestrator issues.
fn obtain_credentials(settings: &Settings, nvs: NvsPartition) -> Result<(String, String)> {
    let hw_id = claim::hardware_id()?;
    let setup_code = Settings::setup_code(nvs.clone())?;
    let api_base = claim::api_base_from_ws_url(&settings.orchestrator_url)?;

    status_led::set(status_led::State::AwaitingClaim);
    let issued = claim::wait_for_claim(&api_base, &hw_id, &setup_code)?;
    status_led::set(status_led::State::Connecting);
    Settings::save_credentials(nvs, &issued.device_id, &issued.device_token)?;

    Ok((issued.device_id, issued.device_token))
}

/// The channel width configured for the band the node is on.
#[cfg(not(esp32c5))]
fn configured_bandwidth(_channel: u8) -> esp_idf_sys::wifi_bandwidth_t {
    let mut bandwidth: esp_idf_sys::wifi_bandwidth_t = 0;
    unsafe {
        esp_idf_sys::esp_wifi_get_bandwidth(esp_idf_sys::wifi_interface_t_WIFI_IF_STA, &mut bandwidth);
    }
    bandwidth
}

/// The channel width configured for the band the node is on. Dual-band chips
/// keep one per band and refuse the single-band query.
#[cfg(esp32c5)]
fn configured_bandwidth(channel: u8) -> esp_idf_sys::wifi_bandwidth_t {
    let mut bandwidths: esp_idf_sys::wifi_bandwidths_t = Default::default();
    unsafe {
        esp_idf_sys::esp_wifi_get_bandwidths(esp_idf_sys::wifi_interface_t_WIFI_IF_STA, &mut bandwidths);
    }
    // 2.4GHz channels are 1-14; anything above is 5GHz.
    if channel > 14 { bandwidths.ghz_5g } else { bandwidths.ghz_2g }
}

/// Log the channel width and signal the router actually granted.
fn log_link_quality() {
    let mut ap: esp_idf_sys::wifi_ap_record_t = unsafe { std::mem::zeroed() };
    unsafe {
        if esp_idf_sys::esp_wifi_sta_get_ap_info(&mut ap) != esp_idf_sys::ESP_OK {
            return;
        }
    }
    let bandwidth = configured_bandwidth(ap.primary);

    let width = if bandwidth == esp_idf_sys::wifi_bandwidth_t_WIFI_BW_HT40 { "40MHz" } else { "20MHz" };
    let secondary = match ap.second {
        esp_idf_sys::wifi_second_chan_t_WIFI_SECOND_CHAN_ABOVE => "above",
        esp_idf_sys::wifi_second_chan_t_WIFI_SECOND_CHAN_BELOW => "below",
        _ => "none",
    };
    info!(
        "link: channel {}, secondary {secondary}, configured {width}, RSSI {} dBm",
        ap.primary, ap.rssi
    );
}

/// One orchestrator connection, from handshake until the link drops.
fn run_session(
    settings: &Settings,
    credentials: &(String, String),
    connector: &Connector,
    watchdog: &mut TWDTDriver<'_>,
    deadline: Instant,
    nvs: NvsPartition,
) -> Result<()> {
    #[cfg(feature = "ota-crash-test")]
    panic!("ota-crash-test: crashing before authentication on purpose");

    let (host, port, path) = parse_url(&settings.orchestrator_url)?;

    let mut tls = TlsStream::connect(host, port, TLS_TIMEOUT_MS)?;
    // Handshake and auth are a strict request/response exchange, so keep the
    // socket blocking until they are done.
    tls.set_nonblocking(false)?;

    let mut ws = WsConn::connect(tls, host, path)?;

    let (device_id, device_token) = credentials;
    info!("Authenticating as {device_id}");
    ws.send_frame(&Frame::auth_with_capabilities(
        device_id,
        device_token,
        Capabilities {
            max_streams: if cfg!(feature = "bench-isolate") { 1 } else { ROUTABLE_STREAMS },
            kind: NodeKind::Microcontroller,
        },
    ))?;

    let response = read_frame_blocking(&mut ws)?;
    if response.frame_type != FrameType::Data || !response.flags.has_ack() {
        return Err(anyhow!("authentication rejected by orchestrator"));
    }
    info!("Authenticated");
    status_led::set(status_led::State::Online);

    // Reaching the orchestrator is what proves a new image: confirm it, or
    // the bootloader would roll back to the previous one on the next reset.
    if !IMAGE_CONFIRMED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        ota::confirm_running(nvs);
    }

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

    // Watched only while relaying: the handshake and auth above have their
    // own timeouts. Dropping the subscription at session end unsubscribes.
    let mut watch = watchdog.watch_current_task()?;
    let mut last_feed = Instant::now();

    #[cfg(feature = "wdt-selftest")]
    let selftest_started = Instant::now();

    loop {
        if Instant::now() >= deadline {
            info!("ending the session for the scheduled update check");
            return Ok(());
        }

        // Once a second is ample against a 45s timeout. Feeding on every
        // pass took the watchdog's lock thousands of times a second under
        // load.
        if last_feed.elapsed() >= Duration::from_secs(1) {
            let _ = watch.feed();
            last_feed = Instant::now();
        }

        #[cfg(feature = "wdt-selftest")]
        if selftest_started.elapsed() > Duration::from_secs(15) {
            warn!("wdt-selftest: hanging the relay loop on purpose");
            loop {
                thread::sleep(Duration::from_secs(1));
            }
        }

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
            info!("{}", profile::task_report());
            // Heap margin, so buffer tuning shows its cost before it shows a
            // crash. The minimum is the low-water mark since boot.
            // Internal RAM shown apart: with PSRAM the totals stay huge
            // while the RAM network buffers need can still run out.
            let internal = esp_idf_sys::MALLOC_CAP_INTERNAL;
            info!(
                "heap: {} KB free, {} KB at lowest; internal {} KB free, {} KB at lowest",
                unsafe { esp_idf_sys::esp_get_free_heap_size() } / 1024,
                unsafe { esp_idf_sys::esp_get_minimum_free_heap_size() } / 1024,
                unsafe { esp_idf_sys::heap_caps_get_free_size(internal) } / 1024,
                unsafe { esp_idf_sys::heap_caps_get_minimum_free_size(internal) } / 1024
            );
            reported_bytes = 0;
            last_report = Instant::now();
        }

        if moved > 0 {
            status_led::activity();
        }

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
