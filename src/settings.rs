//! Device settings, stored in NVS and provisionable over the serial console.
//!
//! Credentials used to be compiled in with env!(), which baked the WiFi
//! password into every binary and meant a rebuild and reflash to move the node
//! to another network — unworkable for a device meant to be handed to
//! volunteers. NVS survives firmware updates, so the same image runs anywhere.
//!
//! Values compiled in with option_env! still work: they seed NVS on first boot,
//! which keeps the existing build-and-flash workflow intact.

use anyhow::{anyhow, Result};
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};
use log::{info, warn};

pub const NAMESPACE: &str = "bentoproxy";
/// Generous enough for a long token; NVS strings are capped anyway.
const VALUE_BUF: usize = 256;

#[derive(Debug, Clone)]
pub struct Settings {
    pub orchestrator_url: String,
    pub device_id: String,
    pub device_token: String,
    pub wifi_ssid: String,
    pub wifi_password: String,
}

/// Compile-time values, when the build supplied them.
fn compiled_in() -> Option<Settings> {
    Some(Settings {
        orchestrator_url: option_env!("ORCHESTRATOR_URL")?.to_string(),
        device_id: option_env!("DEVICE_ID")?.to_string(),
        device_token: option_env!("DEVICE_TOKEN")?.to_string(),
        wifi_ssid: option_env!("WIFI_SSID")?.to_string(),
        wifi_password: option_env!("WIFI_PASSWORD")?.to_string(),
    })
}

impl Settings {
    /// Load from NVS, falling back to compiled-in values and seeding NVS with
    /// them. Returns None when the device has never been provisioned.
    pub fn load(partition: EspDefaultNvsPartition) -> Result<Option<Self>> {
        let mut nvs = EspNvs::new(partition, NAMESPACE, true)?;

        if let Some(stored) = Self::from_nvs(&mut nvs)? {
            info!("settings loaded from NVS (device {})", stored.device_id);
            return Ok(Some(stored));
        }

        match compiled_in() {
            Some(built) => {
                info!("no stored settings; seeding NVS from the compiled-in values");
                built.save(&mut nvs)?;
                Ok(Some(built))
            }
            None => Ok(None),
        }
    }

    fn from_nvs(nvs: &mut EspNvs<NvsDefault>) -> Result<Option<Self>> {
        let mut buf = [0u8; VALUE_BUF];
        let mut get = |key: &str| -> Result<Option<String>> {
            Ok(nvs.get_str(key, &mut buf)?.map(|s| s.to_string()))
        };

        let (Some(orchestrator_url), Some(device_id), Some(device_token), Some(wifi_ssid)) =
            (get("orch_url")?, get("device_id")?, get("device_token")?, get("wifi_ssid")?)
        else {
            return Ok(None);
        };

        Ok(Some(Self {
            orchestrator_url,
            device_id,
            device_token,
            wifi_ssid,
            // An open network legitimately has no password.
            wifi_password: get("wifi_pass")?.unwrap_or_default(),
        }))
    }

    pub fn save(&self, nvs: &mut EspNvs<NvsDefault>) -> Result<()> {
        nvs.set_str("orch_url", &self.orchestrator_url)?;
        nvs.set_str("device_id", &self.device_id)?;
        nvs.set_str("device_token", &self.device_token)?;
        nvs.set_str("wifi_ssid", &self.wifi_ssid)?;
        nvs.set_str("wifi_pass", &self.wifi_password)?;
        info!("settings written to NVS");
        Ok(())
    }

    /// Forget stored credentials, returning the device to setup.
    pub fn erase(partition: EspDefaultNvsPartition) -> Result<()> {
        let mut nvs = EspNvs::new(partition, NAMESPACE, true)?;
        for key in ["orch_url", "device_id", "device_token", "wifi_ssid", "wifi_pass"] {
            // Absent keys are fine: the point is that none remain.
            let _ = nvs.remove(key);
        }
        info!("stored settings erased");
        Ok(())
    }

    /// Prompt over the serial console until every field has a value.
    ///
    /// Runs when NVS is empty and nothing was compiled in, so a freshly
    /// flashed board can be set up without a rebuild.
    pub fn provision(partition: EspDefaultNvsPartition) -> Result<Self> {
        println!();
        println!("=== BentoProxy node setup ===");
        println!("No settings stored. Enter them below; they are saved to NVS.");
        println!();

        let settings = Self {
            wifi_ssid: prompt("WiFi SSID")?,
            wifi_password: prompt_allow_empty("WiFi password (blank for an open network)")?,
            orchestrator_url: prompt_with_default(
                "Orchestrator URL",
                "wss://bentoproxy.com:8443/ws/device",
            )?,
            device_id: prompt("Device ID")?,
            device_token: prompt("Device token")?,
        };

        let mut nvs = EspNvs::new(partition, NAMESPACE, true)?;
        settings.save(&mut nvs)?;
        println!("Saved. Starting node...");
        Ok(settings)
    }
}

fn read_line() -> Result<String> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| anyhow!("serial read failed: {e}"))?;
    Ok(line.trim().to_string())
}

fn prompt(label: &str) -> Result<String> {
    loop {
        print!("{label}: ");
        flush();
        let value = read_line()?;
        if !value.is_empty() {
            return Ok(value);
        }
        warn!("{label} cannot be empty");
    }
}

fn prompt_allow_empty(label: &str) -> Result<String> {
    print!("{label}: ");
    flush();
    read_line()
}

fn prompt_with_default(label: &str, default: &str) -> Result<String> {
    print!("{label} [{default}]: ");
    flush();
    let value = read_line()?;
    Ok(if value.is_empty() { default.to_string() } else { value })
}

fn flush() {
    use std::io::Write;
    let _ = std::io::stdout().flush();
}
