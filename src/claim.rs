//! Getting credentials without the owner ever handling them.
//!
//! The node announces itself to the orchestrator with its hardware id and the
//! setup code printed on its case, then polls. The owner types that code into
//! their dashboard while signed in; the orchestrator creates the device and
//! leaves the credentials for the node to collect over TLS.
//!
//! So the only secret the owner types anywhere is their WiFi password, and the
//! device token never appears on a screen or in a clipboard.

use std::time::Duration;

use anyhow::{anyhow, Result};
use embedded_svc::http::client::Client;
use esp_idf_svc::http::client::{Configuration as HttpConfiguration, EspHttpConnection};
use esp_idf_svc::io::Write;
use log::{info, warn};

/// Model string shown in the dashboard beside a waiting node.
/// Which chip this build is for. Also selects the update channel, since an
/// image only runs on the chip it was built for.
#[cfg(esp32c5)]
pub(crate) const MODEL: &str = "esp32c5";
#[cfg(not(esp32c5))]
pub(crate) const MODEL: &str = "esp32s3";
/// Wait between polls. The owner has to reach their dashboard, so there is no
/// point hammering the server.
const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Re-announce periodically so the node keeps showing as waiting even if the
/// orchestrator pruned an old announcement.
const REANNOUNCE_EVERY: u32 = 12;
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
/// Responses are small JSON objects.
const MAX_RESPONSE: usize = 512;

/// Credentials issued by the orchestrator once an owner claims this node.
pub struct Credentials {
    pub device_id: String,
    pub device_token: String,
}

/// Announce and wait until an owner claims this node.
///
/// Blocks for as long as it takes — a node nobody claims has nothing else to
/// do, and the setup code stays on the serial console meanwhile.
pub fn wait_for_claim(api_base: &str, hw_id: &str, setup_code: &str) -> Result<Credentials> {
    println!();
    println!("=== Waiting to be claimed ===");
    println!("  Open your BentoProxy dashboard and enter this code:");
    println!();
    println!("      {setup_code}");
    println!();
    println!("  Hardware ID: {hw_id}");
    println!();

    let announce_url = format!("{api_base}/api/device/announce");
    let poll_url = format!("{api_base}/api/device/claim/{hw_id}");

    let mut polls: u32 = 0;
    loop {
        if polls % REANNOUNCE_EVERY == 0 {
            match announce(&announce_url, hw_id, setup_code) {
                Ok(()) => info!("announced to the orchestrator; waiting for a claim"),
                // Keep waiting: the network or the server may come back.
                Err(e) => warn!("announce failed: {e}"),
            }
        }

        match poll(&poll_url) {
            Ok(Some(credentials)) => {
                info!("claimed as {}", credentials.device_id);
                return Ok(credentials);
            }
            Ok(None) => {}
            Err(e) => warn!("claim poll failed: {e}"),
        }

        polls = polls.wrapping_add(1);
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Stable per-unit id: the WiFi MAC, which the orchestrator only uses to tell
/// waiting nodes apart.
pub fn hardware_id() -> Result<String> {
    let mut mac = [0u8; 6];
    esp_idf_sys::esp!(unsafe {
        esp_idf_sys::esp_read_mac(mac.as_mut_ptr(), esp_idf_sys::esp_mac_type_t_ESP_MAC_WIFI_STA)
    })?;

    Ok(format!(
        "{MODEL}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    ))
}

/// Turn the orchestrator's WebSocket URL into the API's base URL.
///
/// The device WebSocket runs on its own port; the HTTP API sits behind the
/// ordinary HTTPS front door of the same host.
pub fn api_base_from_ws_url(ws_url: &str) -> Result<String> {
    let rest = ws_url
        .strip_prefix("wss://")
        .or_else(|| ws_url.strip_prefix("ws://"))
        .ok_or_else(|| anyhow!("orchestrator URL must start with ws:// or wss://"))?;

    let authority = rest.split('/').next().unwrap_or(rest);
    let host = authority.split(':').next().unwrap_or(authority);
    if host.is_empty() {
        return Err(anyhow!("orchestrator URL has no host"));
    }

    let scheme = if ws_url.starts_with("wss://") { "https" } else { "http" };
    Ok(format!("{scheme}://{host}"))
}

/// HTTPS client validating against the bundled root certificates. Shared with
/// the update check.
pub(crate) fn http_client(timeout: Duration) -> Result<Client<EspHttpConnection>> {
    let connection = EspHttpConnection::new(&HttpConfiguration {
        crt_bundle_attach: Some(esp_idf_sys::esp_crt_bundle_attach),
        timeout: Some(timeout),
        ..Default::default()
    })?;

    Ok(Client::wrap(connection))
}

fn announce(url: &str, hw_id: &str, setup_code: &str) -> Result<()> {
    let body = format!(
        "hw_id={}&claim_code={}&model={}",
        urlencode(hw_id),
        urlencode(setup_code),
        urlencode(MODEL)
    );
    let length = body.len().to_string();
    let headers = [
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Content-Length", length.as_str()),
    ];

    let mut client = http_client(HTTP_TIMEOUT)?;
    let mut request = client.post(url, &headers)?;
    request.write_all(body.as_bytes())?;
    request.flush()?;

    let response = request.submit()?;
    let status = response.status();
    if !(200..300).contains(&status) {
        return Err(anyhow!("orchestrator answered {status}"));
    }

    Ok(())
}

fn poll(url: &str) -> Result<Option<Credentials>> {
    let mut client = http_client(HTTP_TIMEOUT)?;
    let request = client.get(url)?;
    let mut response = request.submit()?;

    let status = response.status();
    if !(200..300).contains(&status) {
        return Err(anyhow!("orchestrator answered {status}"));
    }

    let mut buf = [0u8; MAX_RESPONSE];
    let mut len = 0;
    while len < buf.len() {
        match response.read(&mut buf[len..])? {
            0 => break,
            n => len += n,
        }
    }

    let body = std::str::from_utf8(&buf[..len]).unwrap_or_default();
    match (json_string(body, "device_id"), json_string(body, "device_token")) {
        (Some(device_id), Some(device_token)) => Ok(Some(Credentials { device_id, device_token })),
        // "pending" is the normal answer until an owner enters the code.
        _ => Ok(None),
    }
}

/// Read one string value out of a flat JSON object.
///
/// The responses are a fixed handful of string fields, so this avoids pulling
/// a JSON parser into the firmware.
pub(crate) fn json_string(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let after_key = &body[body.find(&needle)? + needle.len()..];
    let after_colon = &after_key[after_key.find(':')? + 1..];
    let start = after_colon.find('"')? + 1;
    let rest = &after_colon[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn urlencode(input: &str) -> String {
    input
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_fields_from_a_response() {
        let body = r#"{"status":"claimed","device_id":"dev-1a2b3c4d","device_token":"bento_ff00"}"#;
        assert_eq!(json_string(body, "device_id").unwrap(), "dev-1a2b3c4d");
        assert_eq!(json_string(body, "device_token").unwrap(), "bento_ff00");
        assert!(json_string(body, "missing").is_none());
    }

    #[test]
    fn pending_response_yields_nothing() {
        let body = r#"{"status":"pending"}"#;
        assert!(json_string(body, "device_id").is_none());
    }

    #[test]
    fn derives_the_api_base() {
        assert_eq!(
            api_base_from_ws_url("wss://bentoproxy.com:8443/ws/device").unwrap(),
            "https://bentoproxy.com"
        );
        assert_eq!(
            api_base_from_ws_url("ws://192.168.1.5:8080/ws/device").unwrap(),
            "http://192.168.1.5"
        );
        assert!(api_base_from_ws_url("https://bentoproxy.com").is_err());
    }
}
