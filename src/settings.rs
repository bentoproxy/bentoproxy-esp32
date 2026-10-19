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

/// Where to reach the orchestrator when the owner did not say otherwise.
///
/// Port 443, not 8443: both reach the same route, but guest, hotel and
/// corporate networks routinely allow only 443 outbound. A node on a guest
/// network was being reset every couple of minutes on 8443.
pub const DEFAULT_ORCHESTRATOR_URL: &str = "wss://bentoproxy.com/ws/device";
/// NVS key holding this unit's setup code.
pub const SETUP_CODE_KEY: &str = "setup_code";
/// Characters for the setup code: 32 symbols, none of them easily misread off
/// a printed label.
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
/// Eight characters gives 40 bits, which a rate-limited claim endpoint makes
/// hopeless to guess.
const SETUP_CODE_LEN: usize = 8;

#[derive(Debug, Clone)]
pub struct Settings {
    pub orchestrator_url: String,
    pub wifi_ssid: String,
    pub wifi_password: String,
    /// Absent until an owner claims this node; see the claim module.
    pub device_id: Option<String>,
    pub device_token: Option<String>,
}

/// Compile-time values, when the build supplied them.
///
/// Only WiFi is required: a build without credentials is the normal case now,
/// since the node obtains them by being claimed.
fn compiled_in() -> Option<Settings> {
    Some(Settings {
        orchestrator_url: option_env!("ORCHESTRATOR_URL")
            .unwrap_or(DEFAULT_ORCHESTRATOR_URL)
            .to_string(),
        wifi_ssid: option_env!("WIFI_SSID")?.to_string(),
        wifi_password: option_env!("WIFI_PASSWORD")?.to_string(),
        device_id: option_env!("DEVICE_ID").map(str::to_string),
        device_token: option_env!("DEVICE_TOKEN").map(str::to_string),
    })
}

impl Settings {
    /// Load from NVS, falling back to compiled-in values and seeding NVS with
    /// them. Returns None when the device has never been provisioned.
    pub fn load(partition: EspDefaultNvsPartition) -> Result<Option<Self>> {
        let mut nvs = EspNvs::new(partition, NAMESPACE, true)?;

        if let Some(mut stored) = Self::from_nvs(&mut nvs)? {
            // Nodes provisioned before the move to 443 carry the old port in
            // NVS; re-point them rather than making the owner redo setup.
            if stored.orchestrator_url.contains(":8443") {
                info!("migrating the stored orchestrator URL to port 443");
                stored.orchestrator_url = DEFAULT_ORCHESTRATOR_URL.to_string();
                nvs.set_str("orch_url", DEFAULT_ORCHESTRATOR_URL)?;
            }

            match stored.device_id.as_deref() {
                Some(device_id) => info!("settings loaded from NVS (device {device_id})"),
                None => info!("WiFi settings loaded from NVS; this node is not claimed yet"),
            }
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

        // WiFi is what provisioning establishes; credentials arrive later from
        // a claim, so their absence is not a reason to re-run setup.
        let Some(wifi_ssid) = get("wifi_ssid")? else {
            return Ok(None);
        };

        Ok(Some(Self {
            orchestrator_url: get("orch_url")?
                .unwrap_or_else(|| DEFAULT_ORCHESTRATOR_URL.to_string()),
            wifi_ssid,
            // An open network legitimately has no password.
            wifi_password: get("wifi_pass")?.unwrap_or_default(),
            device_id: get("device_id")?,
            device_token: get("device_token")?,
        }))
    }

    pub fn save(&self, nvs: &mut EspNvs<NvsDefault>) -> Result<()> {
        nvs.set_str("orch_url", &self.orchestrator_url)?;
        nvs.set_str("wifi_ssid", &self.wifi_ssid)?;
        nvs.set_str("wifi_pass", &self.wifi_password)?;
        if let Some(ref device_id) = self.device_id {
            nvs.set_str("device_id", device_id)?;
        }
        if let Some(ref token) = self.device_token {
            nvs.set_str("device_token", token)?;
        }
        info!("settings written to NVS");
        Ok(())
    }

    /// Store credentials issued by a claim.
    pub fn save_credentials(
        partition: EspDefaultNvsPartition,
        device_id: &str,
        device_token: &str,
    ) -> Result<()> {
        let mut nvs = EspNvs::new(partition, NAMESPACE, true)?;
        nvs.set_str("device_id", device_id)?;
        nvs.set_str("device_token", device_token)?;
        info!("credentials stored for {device_id}");
        Ok(())
    }

    /// This unit's setup code, generated once and kept for the life of the
    /// device so a printed label stays correct.
    ///
    /// Deliberately not derived from the MAC: the MAC is the setup AP's own
    /// BSSID, broadcast in every beacon, so anyone in range could have
    /// computed it and claimed or reconfigured the node.
    pub fn setup_code(partition: EspDefaultNvsPartition) -> Result<String> {
        let mut nvs = EspNvs::new(partition, NAMESPACE, true)?;

        let mut buf = [0u8; 32];
        if let Some(code) = nvs.get_str(SETUP_CODE_KEY, &mut buf)? {
            return Ok(code.to_string());
        }

        let code: String = (0..SETUP_CODE_LEN)
            .map(|_| {
                let r = unsafe { esp_idf_sys::esp_random() };
                CODE_ALPHABET[(r % CODE_ALPHABET.len() as u32) as usize] as char
            })
            .collect();

        nvs.set_str(SETUP_CODE_KEY, &code)?;
        info!("generated this device's setup code");
        Ok(code)
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
            orchestrator_url: prompt_with_default("Orchestrator URL", DEFAULT_ORCHESTRATOR_URL)?,
            // Obtained by being claimed, not typed in.
            device_id: None,
            device_token: None,
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
