//! First-boot setup over a captive portal.
//!
//! An unconfigured node brings up its own access point, named after the last
//! two bytes of its MAC and protected by the setup code printed on the case.
//! Joining it opens a page listing the networks the node can actually see,
//! which is the point: the ESP32 radio is 2.4 GHz only, so a scan list makes
//! the 5 GHz network a customer cannot use simply absent rather than a
//! mysterious failure.
//!
//! Credentials go to NVS and the node reboots into its normal path.

use std::net::{Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Result};
use embedded_svc::wifi::{AccessPointConfiguration, ClientConfiguration, Configuration};
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::http::server::{Configuration as HttpConfig, EspHttpServer};
use esp_idf_svc::http::Method;
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs};
use esp_idf_svc::wifi::{BlockingWifi, EspWifi};
use esp_idf_svc::io::Write;
use log::{info, warn};

use crate::settings::Settings;

/// The portal's address. Matches the IDF SoftAP default, so DHCP needs no
/// extra configuration.
const PORTAL_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 71, 1);
/// Body cap for the save request; the form is far smaller.
const MAX_BODY: usize = 1024;

/// Run setup until new WiFi details arrive, or until `timeout` passes.
///
/// A first-time setup waits indefinitely. A node that lost its saved network
/// waits only `timeout`, then returns so the caller can reboot and retry the
/// old network: a router reboot must not strand a node in setup mode, while a
/// node that really moved keeps offering setup on every cycle.
pub fn run(
    modem: impl esp_idf_hal::peripheral::Peripheral<P = esp_idf_hal::modem::Modem> + 'static,
    sys_loop: EspSystemEventLoop,
    nvs: EspDefaultNvsPartition,
    timeout: Option<Duration>,
    unreachable_network: Option<String>,
) -> Result<()> {
    let ap_ssid = ap_name()?;
    let setup_code = Settings::setup_code(nvs.clone())?;
    let claimed = Settings::is_claimed(nvs.clone());

    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(modem, sys_loop.clone(), Some(nvs.clone()))?,
        sys_loop,
    )?;

    // Mixed mode: the AP serves the portal while the station interface scans.
    wifi.set_configuration(&Configuration::Mixed(
        ClientConfiguration::default(),
        AccessPointConfiguration {
            ssid: ap_ssid
                .as_str()
                .try_into()
                .map_err(|_| anyhow!("AP SSID too long"))?,
            password: setup_code
                .as_str()
                .try_into()
                .map_err(|_| anyhow!("setup code too long"))?,
            auth_method: embedded_svc::wifi::AuthMethod::WPA2Personal,
            channel: 1,
            max_connections: 4,
            ..Default::default()
        },
    ))?;
    wifi.start()?;
    if let Err(e) = advertise_dns(&mut wifi) {
        warn!("phones will not be told about our resolver, so the setup page \
               will not open by itself: {e}");
    }

    println!();
    println!("=== BentoProxy node setup ===");
    println!("  Join WiFi network: {ap_ssid}");
    println!("  Setup code:        {setup_code}");
    println!("  Then open:         http://{PORTAL_IP}/");
    println!();

    let networks = Arc::new(Mutex::new(scan(&mut wifi)));
    let saved = Arc::new(AtomicBool::new(false));
    let _server = serve(
        nvs,
        networks.clone(),
        saved.clone(),
        ap_ssid.clone(),
        setup_code.clone(),
        claimed,
        unreachable_network,
    )?;
    let _dns = redirect_dns();

    let deadline = timeout.map(|t| std::time::Instant::now() + t);

    // Rescan periodically: a customer may switch their router's band or move
    // the node while this page is open.
    while !saved.load(Ordering::Relaxed) {
        if deadline.is_some_and(|d| std::time::Instant::now() >= d) {
            info!("setup timed out; retrying the saved network");
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(15));
        if !saved.load(Ordering::Relaxed) {
            let fresh = scan(&mut wifi);
            if let Ok(mut list) = networks.lock() {
                *list = fresh;
            }
        }
    }

    info!("setup complete");
    std::thread::sleep(Duration::from_millis(500)); // Let the reply flush.
    Ok(())
}

/// AP name for this unit. The MAC is fine here: it is the AP's own BSSID,
/// broadcast in every beacon. The setup code is not derived from it — see
/// Settings::setup_code.
fn ap_name() -> Result<String> {
    let mut mac = [0u8; 6];
    esp_idf_sys::esp!(unsafe {
        esp_idf_sys::esp_read_mac(mac.as_mut_ptr(), esp_idf_sys::esp_mac_type_t_ESP_MAC_WIFI_STA)
    })?;
    Ok(format!("BentoProxy-{:02X}{:02X}", mac[4], mac[5]))
}

fn scan(wifi: &mut BlockingWifi<EspWifi<'static>>) -> Vec<(String, i8)> {
    match wifi.scan() {
        Ok(aps) => {
            let mut seen: Vec<(String, i8)> = Vec::new();
            for ap in aps {
                let ssid = ap.ssid.as_str().to_string();
                if ssid.is_empty() {
                    continue; // Hidden network: nothing to show.
                }
                match seen.iter_mut().find(|(name, _)| *name == ssid) {
                    // Same network on several channels: keep the strongest.
                    Some((_, rssi)) if *rssi < ap.signal_strength => *rssi = ap.signal_strength,
                    Some(_) => {}
                    None => seen.push((ssid, ap.signal_strength)),
                }
            }
            seen.sort_by_key(|(_, rssi)| -(*rssi as i32));
            info!("scan found {} networks", seen.len());
            seen
        }
        Err(e) => {
            warn!("scan failed: {e:?}");
            Vec::new()
        }
    }
}

fn serve(
    nvs: EspDefaultNvsPartition,
    networks: Arc<Mutex<Vec<(String, i8)>>>,
    saved: Arc<AtomicBool>,
    ap_ssid: String,
    setup_code: String,
    claimed: bool,
    unreachable_network: Option<String>,
) -> Result<EspHttpServer<'static>> {
    // The default 6KB handler stack leaves little room for building a page
    // and holding the request body at once.
    let mut server = EspHttpServer::new(&HttpConfig {
        stack_size: 10240,
        // For the catch-all below. Handlers are matched in registration
        // order, so the exact paths above it still win.
        uri_match_wildcard: true,
        ..HttpConfig::default()
    })?;

    let page_networks = networks.clone();
    let page_code = setup_code.clone();
    server.fn_handler("/", Method::Get, move |req| {
        let list = page_networks.lock().map(|l| l.clone()).unwrap_or_default();
        let mut response = req.into_ok_response()?;
        response.write_all(
            setup_page(&list, &ap_ssid, &page_code, claimed, unreachable_network.as_deref())
                .as_bytes(),
        )?;
        Ok::<(), anyhow::Error>(())
    })?;

    let save_nvs = nvs.clone();
    server.fn_handler("/save", Method::Post, move |mut req| {
        // A form can arrive split across reads; stop at EOF or the cap.
        let mut buf = [0u8; MAX_BODY];
        let mut len = 0;
        while len < buf.len() {
            match req.read(&mut buf[len..])? {
                0 => break,
                n => len += n,
            }
        }
        let body = std::str::from_utf8(&buf[..len]).unwrap_or_default().to_string();

        info!("setup submitted ({} bytes)", body.len());
        match store(&body, save_nvs.clone()) {
            Ok(ssid) => {
                let mut response = req.into_ok_response()?;
                response.write_all(saved_page(&ssid).as_bytes())?;
                saved.store(true, Ordering::Relaxed);
            }
            Err(e) => {
                warn!("setup rejected: {e}");
                // Render the reason as a normal page: a handler that returns
                // Err here produces the server's own opaque 500, which tells
                // the owner nothing about what to fix.
                let mut response = req.into_ok_response()?;
                response.write_all(error_page(&e.to_string()).as_bytes())?;
            }
        }
        Ok::<(), anyhow::Error>(())
    })?;

    // Phones probe these URLs to decide whether a network is "captive"; a
    // redirect is what makes the setup page open by itself. `no-store`
    // matters: iOS reuses a cached probe result and would skip the check.
    for probe in [
        "/generate_204",               // Android
        "/gen_204",                    // Android, older
        "/hotspot-detect.html",        // iOS, macOS
        "/library/test/success.html",  // iOS, older
        "/connecttest.txt",            // Windows
        "/ncsi.txt",                   // Windows
        "/canonical.html",             // Firefox
    ] {
        server.fn_handler(probe, Method::Get, move |req| {
            redirect_to_portal(req)
        })?;
    }

    // Anything else, because probe paths change between OS versions and our
    // own 404 would read as a working internet connection. Registered last
    // so the real pages keep their handlers.
    server.fn_handler("/*", Method::Get, move |req| redirect_to_portal(req))?;

    Ok(server)
}

/// Parse the form and write the settings to NVS.
fn store(body: &str, nvs: EspDefaultNvsPartition) -> Result<String> {
    let fields = parse_form(body);
    let get = |key: &str| fields.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());

    let ssid = get("ssid").filter(|s| !s.is_empty()).ok_or_else(|| anyhow!("no network selected"))?;

    let settings = Settings {
        wifi_ssid: ssid.clone(),
        // An open network has no password, so empty is valid here.
        wifi_password: get("password").unwrap_or_default(),
        orchestrator_url: get("orch_url")
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| crate::settings::DEFAULT_ORCHESTRATOR_URL.to_string()),
        // The owner claims this node from their dashboard instead of pasting
        // credentials into a form.
        device_id: None,
        device_token: None,
    };

    let mut nvs = EspNvs::new(nvs, crate::settings::NAMESPACE, true)?;
    settings.save(&mut nvs)?;
    Ok(ssid)
}

/// Decode an application/x-www-form-urlencoded body.
fn parse_form(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((percent_decode(key), percent_decode(value)))
        })
        .collect()
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(&input[i + 1..i + 3], 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    // Not a valid escape: keep the character as typed.
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

/// Send a probe to the setup page, uncached.
fn redirect_to_portal(req: esp_idf_svc::http::server::Request<&mut esp_idf_svc::http::server::EspHttpConnection>) -> Result<()> {
    req.into_response(
        302,
        None,
        &[
            ("Location", &format!("http://{PORTAL_IP}/")),
            ("Cache-Control", "no-store"),
        ],
    )?;
    Ok(())
}

/// Hand this node out as the DHCP DNS server.
///
/// The resolver below is useless until clients are told to use it: IDF's
/// softAP offers a gateway but no DNS server, so a joining phone has nowhere
/// to send its captive-portal check (`captive.apple.com` for iOS) and the
/// setup page never opens by itself. The DHCP server only picks the setting
/// up while it is stopped, so it is restarted around the change.
fn advertise_dns(wifi: &mut BlockingWifi<EspWifi<'static>>) -> Result<()> {
    /// dhcpserver.h's OFFER_DNS, which the bindings do not expose.
    const OFFER_DNS: u8 = 0x02;

    let netif = esp_idf_svc::handle::RawHandle::handle(wifi.wifi().ap_netif());
    if netif.is_null() {
        return Err(anyhow!("the AP has no network interface"));
    }

    unsafe {
        // Not an error if it was never started.
        esp_idf_sys::esp_netif_dhcps_stop(netif);

        let mut offer = OFFER_DNS;
        esp_idf_sys::esp!(esp_idf_sys::esp_netif_dhcps_option(
            netif,
            esp_idf_sys::esp_netif_dhcp_option_mode_t_ESP_NETIF_OP_SET,
            esp_idf_sys::esp_netif_dhcp_option_id_t_ESP_NETIF_DOMAIN_NAME_SERVER,
            &mut offer as *mut u8 as *mut core::ffi::c_void,
            core::mem::size_of_val(&offer) as u32,
        ))?;

        let mut dns: esp_idf_sys::esp_netif_dns_info_t = core::mem::zeroed();
        dns.ip.type_ = esp_idf_sys::ESP_IPADDR_TYPE_V4 as u8;
        // esp_ip4_addr holds the first octet in the low byte.
        dns.ip.u_addr.ip4.addr = u32::from_le_bytes(PORTAL_IP.octets());
        esp_idf_sys::esp!(esp_idf_sys::esp_netif_set_dns_info(
            netif,
            esp_idf_sys::esp_netif_dns_type_t_ESP_NETIF_DNS_MAIN,
            &mut dns,
        ))?;

        esp_idf_sys::esp!(esp_idf_sys::esp_netif_dhcps_start(netif))?;
    }

    info!("DHCP now points clients at {PORTAL_IP} for DNS");
    Ok(())
}

/// Answer every DNS query with the portal's address.
///
/// Without this a phone's captive-portal check cannot resolve anything, so no
/// setup page appears and the customer is left typing in an IP address.
fn redirect_dns() -> Option<std::thread::JoinHandle<()>> {
    let socket = match UdpSocket::bind("0.0.0.0:53") {
        Ok(socket) => socket,
        Err(e) => {
            warn!("captive DNS unavailable, setup needs the IP address: {e}");
            return None;
        }
    };

    std::thread::Builder::new()
        .stack_size(4096)
        .name("captive-dns".into())
        .spawn(move || {
            let mut query = [0u8; 512];
            loop {
                let Ok((len, from)) = socket.recv_from(&mut query) else {
                    continue;
                };
                if let Some(reply) = dns_reply(&query[..len]) {
                    let _ = socket.send_to(&reply, from);
                }
            }
        })
        .ok()
}

/// Build an A-record answer pointing at the portal, echoing the question.
fn dns_reply(query: &[u8]) -> Option<Vec<u8>> {
    // Header plus at least one question.
    if query.len() < 12 {
        return None;
    }

    let questions = u16::from_be_bytes([query[4], query[5]]);
    if questions == 0 {
        return None;
    }

    // Walk the first question's labels to find where it ends.
    let mut pos = 12;
    while pos < query.len() && query[pos] != 0 {
        pos += 1 + query[pos] as usize;
    }
    let question_end = pos + 5; // null label + qtype + qclass
    if question_end > query.len() {
        return None;
    }

    // Phones ask for AAAA alongside A. Answering those with an A record
    // leaves iOS waiting on a reply it cannot use; an empty NOERROR makes it
    // fall back to IPv4 at once.
    let qtype = u16::from_be_bytes([query[pos + 1], query[pos + 2]]);
    const TYPE_A: u16 = 1;
    let answers: u16 = if qtype == TYPE_A { 1 } else { 0 };

    let mut reply = Vec::with_capacity(question_end + 16);
    reply.extend_from_slice(&query[0..2]); // transaction id
    reply.extend_from_slice(&[0x81, 0x80]); // response, recursion available
    reply.extend_from_slice(&[0x00, 0x01]); // one question
    reply.extend_from_slice(&answers.to_be_bytes());
    reply.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // no authority or additional
    reply.extend_from_slice(&query[12..question_end]);

    if answers == 0 {
        return Some(reply);
    }

    reply.extend_from_slice(&[0xC0, 0x0C]); // pointer to the question's name
    reply.extend_from_slice(&[0x00, 0x01]); // type A
    reply.extend_from_slice(&[0x00, 0x01]); // class IN
    reply.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60s
    reply.extend_from_slice(&[0x00, 0x04]); // address length
    reply.extend_from_slice(&PORTAL_IP.octets());

    Some(reply)
}

fn setup_page(
    networks: &[(String, i8)],
    ap_ssid: &str,
    setup_code: &str,
    claimed: bool,
    unreachable_network: Option<&str>,
) -> String {
    let default_url = crate::settings::DEFAULT_ORCHESTRATOR_URL;

    // A node that moved has nothing to claim, only a network to change.
    let lost_notice = match unreachable_network {
        Some(ssid) => format!(
            "<p class=\"note\">This node could not connect to <strong>{}</strong>. \
             Choose the network it should use now.</p>",
            escape(ssid)
        ),
        None => String::new(),
    };
    let next_step = if claimed {
        "This node is already linked to your account — once it joins the network \
         it reconnects by itself."
            .to_string()
    } else {
        format!(
            "Next you will enter this node's setup code <strong>{setup_code}</strong> in \
             your BentoProxy dashboard to link it to your account."
        )
    };
    let options = if networks.is_empty() {
        "<option value=\"\">No networks found — wait a moment and reload</option>".to_string()
    } else {
        networks
            .iter()
            .map(|(ssid, rssi)| {
                format!(
                    "<option value=\"{}\">{} ({})</option>",
                    escape(ssid),
                    escape(ssid),
                    signal_label(*rssi)
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };


    format!(
        r#"<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{ap_ssid} setup</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
         margin: 0; padding: 24px 16px; max-width: 26rem; margin-inline: auto; }}
  h1 {{ font-size: 1.3rem; margin: 0 0 .25rem; }}
  p.sub {{ margin: 0 0 1.5rem; opacity: .7; font-size: .9rem; }}
  label {{ display: block; margin-top: 1rem; font-weight: 600; font-size: .9rem; }}
  select, input {{ width: 100%; padding: .6rem; margin-top: .3rem; font-size: 1rem;
                   border: 1px solid rgba(128,128,128,.5); border-radius: 8px;
                   background: transparent; color: inherit; box-sizing: border-box; }}
  button {{ width: 100%; margin-top: 1.5rem; padding: .8rem; font-size: 1rem; font-weight: 600;
            border: 0; border-radius: 8px; background: #2563eb; color: #fff; }}
  details {{ margin-top: 1.5rem; font-size: .9rem; }}
  .note {{ margin-top: 1.5rem; padding: .75rem; border-radius: 8px;
           background: rgba(128,128,128,.12); font-size: .85rem; }}
</style></head>
<body>
  <h1>Set up your node</h1>
  <p class="sub">{ap_ssid}</p>
  {lost_notice}
  <form method="POST" action="/save">
    <label for="ssid">WiFi network</label>
    <select id="ssid" name="ssid" required>{options}</select>

    <label for="password">WiFi password</label>
    <input id="password" name="password" type="password" autocomplete="off"
           placeholder="Leave blank for an open network">

    <details>
      <summary>Advanced</summary>
      <label for="orch_url">Orchestrator URL</label>
      <input id="orch_url" name="orch_url" value="{default_url}">
    </details>

    <button type="submit">Save and connect</button>
  </form>
  <p class="note">{next_step} Only 2.4 GHz networks appear above: this node has no
  5 GHz radio.</p>
</body></html>"#
    )
}

fn saved_page(ssid: &str) -> String {
    format!(
        r#"<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Saved</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
         margin: 0; padding: 24px 16px; max-width: 26rem; margin-inline: auto; }}
  h1 {{ font-size: 1.3rem; }}
</style></head>
<body>
  <h1>Saved</h1>
  <p>The node is restarting and will join <strong>{}</strong>.</p>
  <p>This setup network is about to disappear — reconnect your phone to your
  usual WiFi. If the node cannot join, it reopens setup automatically.</p>
</body></html>"#,
        escape(ssid)
    )
}

fn error_page(message: &str) -> String {
    format!(
        r#"<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Setup failed</title></head>
<body style="font: 16px/1.6 system-ui, sans-serif; padding: 24px; max-width: 26rem; margin: auto">
  <h1 style="font-size:1.3rem">Could not save</h1>
  <p>{}</p>
  <p><a href="/">Back to setup</a></p>
</body></html>"#,
        escape(message)
    )
}

fn signal_label(rssi: i8) -> &'static str {
    match rssi {
        -55..=0 => "strong",
        -70..=-56 => "good",
        -80..=-71 => "weak",
        _ => "very weak",
    }
}

fn escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
