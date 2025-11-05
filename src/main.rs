//! BentoProxy ESP32 Node Firmware
//!
//! This firmware connects to the BentoProxy orchestrator via WebSocket,
//! authenticates, and handles proxy streams by creating TCP connections.
//!
//! Hardware: ESP32-S3 (or compatible)
//! Network: WiFi
//! Protocol: WebSocket with binary frames (see bentoproxy-protocol)

#![no_std]
#![no_main]

use esp_idf_svc::{
    eventloop::EspSystemEventLoop,
    hal::{peripherals::Peripherals, prelude::*},
    nvs::EspDefaultNvsPartition,
    wifi::{AsyncWifi, ClientConfiguration, Configuration, EspWifi},
};
use esp_idf_sys as _; // Required for esp-idf bindings
use log::{error, info, warn};

// Protocol imports
use bentoproxy_protocol::{Frame, FrameType};

const ORCHESTRATOR_URL: &str = env!("ORCHESTRATOR_URL", "wss://bentoproxy.com:8443/ws/device");
const DEVICE_ID: &str = env!("DEVICE_ID", "esp32-dev-001");
const DEVICE_TOKEN: &str = env!("DEVICE_TOKEN");
const WIFI_SSID: &str = env!("WIFI_SSID");
const WIFI_PASSWORD: &str = env!("WIFI_PASSWORD");

const MAX_CONCURRENT_STREAMS: usize = 8;

#[no_mangle]
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
    let wifi = match init_wifi(
        peripherals.modem,
        sys_loop.clone(),
        Some(nvs.clone()),
    ) {
        Ok(wifi) => wifi,
        Err(e) => {
            error!("Failed to initialize WiFi: {:?}", e);
            panic!();
        }
    };

    info!("WiFi initialized, connecting...");
    // TODO: Connect WiFi (async)

    info!("Connected to WiFi");

    // Main loop: connect to orchestrator
    loop {
        info!("Connecting to orchestrator: {}", ORCHESTRATOR_URL);

        match connect_to_orchestrator() {
            Ok(()) => {
                info!("Orchestrator connection closed normally");
            }
            Err(e) => {
                error!("Orchestrator error: {:?}", e);
                warn!("Reconnecting in 5 seconds...");
                // TODO: Sleep 5 seconds
            }
        }
    }
}

/// Initialize WiFi with provided credentials
fn init_wifi(
    modem: impl esp_idf_svc::hal::peripheral::Peripheral<P = esp_idf_svc::hal::modem::Modem> + 'static,
    sys_loop: EspSystemEventLoop,
    nvs: Option<EspDefaultNvsPartition>,
) -> anyhow::Result<EspWifi<'static>> {
    let mut wifi = EspWifi::new(modem, sys_loop.clone(), nvs)?;

    let wifi_config = Configuration::Client(ClientConfiguration {
        ssid: WIFI_SSID.into(),
        password: WIFI_PASSWORD.into(),
        ..Default::default()
    });

    wifi.set_configuration(&wifi_config)?;
    wifi.start()?;
    wifi.connect()?;

    // Wait for IP
    info!("Waiting for IP address...");
    // TODO: Wait for DHCP

    Ok(wifi)
}

/// Connect to orchestrator and handle frames
fn connect_to_orchestrator() -> anyhow::Result<()> {
    // TODO: Implement WebSocket connection
    // 1. TCP connect to orchestrator
    // 2. WebSocket handshake
    // 3. Send AUTH frame
    // 4. Wait for AUTH ACK
    // 5. Main message loop (receive frames, dispatch)

    info!("TODO: WebSocket connection not yet implemented");

    Ok(())
}

/// Handle OPEN frame - create TCP connection to target
fn handle_open(frame: Frame) {
    info!("TODO: handle_open not yet implemented");
    // 1. Parse host and port from frame
    // 2. Create TCP connection
    // 3. Send ACK frame
    // 4. Spawn task to relay data bidirectionally
}

/// Handle DATA frame - write to TCP connection
fn handle_data(frame: Frame) {
    info!("TODO: handle_data not yet implemented");
    // 1. Find stream by stream_id
    // 2. Write payload to TCP connection
}

/// Handle CLOSE frame - close TCP connection
fn handle_close(stream_id: u32) {
    info!("TODO: handle_close not yet implemented");
    // 1. Find stream by stream_id
    // 2. Close TCP connection
    // 3. Remove from stream map
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    error!("PANIC: {:?}", info);
    loop {}
}
