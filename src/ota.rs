//! Signed over-the-air updates.
//!
//! A node sitting in someone else's home cannot be reflashed over USB, so
//! every fix has to arrive over the network — which also makes the update
//! channel the most valuable thing an attacker could take over. Updates are
//! therefore accepted only when the image's SHA-256 digest carries an Ed25519
//! signature from the release key. The node embeds the public key; the
//! private key never leaves the release machine (see tools/fwsign).
//!
//! The orchestrator publishes a small manifest — version, size, digest,
//! signature, image name — next to the images. The node downloads only when
//! the manifest is newer than itself and the signature over the claimed digest
//! verifies, streams the image straight into the inactive slot while hashing
//! it, and switches slots only if the digest matches. A new image boots on
//! probation (CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE) until `confirm_running`.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_compact::{PublicKey, Signature};
use esp_idf_svc::io::Read;
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};
use esp_idf_svc::ota::EspOta;
use log::{info, warn};
use sha2::{Digest, Sha256};

/// Release key. Rotating it means shipping an image signed with the old key
/// that embeds the new one.
const PUBLIC_KEY: &[u8; 32] = include_bytes!("../keys/firmware-signing.pub");
/// Manifests are a few hundred bytes; anything bigger is not one.
const MAX_MANIFEST: usize = 2048;
/// Must fit an app slot (3MB, see partitions.csv).
const MAX_IMAGE: usize = 3 * 1024 * 1024;
const CHUNK: usize = 4096;
/// Version installed but not yet proven by reaching the orchestrator.
const PENDING_KEY: &str = "ota_pending";
/// Version that failed its first boot and must not be installed again.
const BAD_KEY: &str = "ota_bad";

/// This build's version, set by tools/release-firmware.sh. Development builds
/// are 0, so any release supersedes them.
pub fn firmware_version() -> u64 {
    option_env!("BENTO_FW_VERSION")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

pub enum Outcome {
    /// No release, or none newer than this build.
    UpToDate,
    /// A verified image is in the other slot; reboot to run it.
    Installed { version: u64 },
}

struct Manifest {
    version: u64,
    size: usize,
    sha256: [u8; 32],
    signature: [u8; 64],
    image: String,
}

/// Settle the outcome of the last update, once per boot, before checking for
/// another.
///
/// Rollback alone would loop: a release that crashes on its first boot is
/// rolled back, the old image sees the same "newer" release, installs it
/// again, and so on, burning the owner's bandwidth and flash on every cycle.
/// So a version is recorded as pending when installed, cleared once it proves
/// itself (`confirm_running`), and if the node comes back up on a different
/// version with one still pending, that release failed and is never retried.
pub fn reconcile_after_boot(partition: EspDefaultNvsPartition) {
    let Ok(mut nvs) = open(partition) else { return };
    let Ok(Some(pending)) = nvs.get_u64(PENDING_KEY) else { return };

    let running = firmware_version();
    if pending != running {
        warn!(
            "ota: version {pending} did not survive its first boot and was rolled back to \
             {running}; it will not be installed again"
        );
        let _ = nvs.set_u64(BAD_KEY, pending);
        let _ = nvs.remove(PENDING_KEY);
    }
    // pending == running: this is the new image's trial boot. Leave the
    // marker until it proves itself.
}

/// Check the orchestrator for a newer release and install it if it verifies.
pub fn check_and_install(api_base: &str, partition: EspDefaultNvsPartition) -> Result<Outcome> {
    let current = firmware_version();
    let manifest_url = format!("{api_base}/api/device/firmware/manifest.json");

    let Some(body) = fetch_small(&manifest_url)? else {
        info!("ota: no release published");
        return Ok(Outcome::UpToDate);
    };
    let manifest = parse_manifest(&body)?;

    if manifest.version <= current {
        info!("ota: up to date (running {current}, published {})", manifest.version);
        return Ok(Outcome::UpToDate);
    }

    let mut nvs = open(partition)?;
    if nvs.get_u64(BAD_KEY).ok().flatten() == Some(manifest.version) {
        info!("ota: skipping version {}, which failed here before", manifest.version);
        return Ok(Outcome::UpToDate);
    }
    if manifest.size == 0 || manifest.size > MAX_IMAGE {
        bail!("ota: manifest declares an implausible size {}", manifest.size);
    }

    // Reject a forged manifest before downloading a megabyte for nothing.
    verify_signature(&manifest.sha256, &manifest.signature)?;
    info!(
        "ota: installing {} -> {} ({} KB)",
        current,
        manifest.version,
        manifest.size / 1024
    );

    let image_url = format!("{api_base}/api/device/firmware/{}", manifest.image);
    download_into_inactive_slot(&image_url, &manifest)?;

    // Recorded after the slot is switched and before rebooting into it.
    nvs.set_u64(PENDING_KEY, manifest.version)?;

    info!("ota: version {} verified and installed", manifest.version);
    Ok(Outcome::Installed { version: manifest.version })
}

/// Confirm the running image after it has proven itself, ending its
/// probation. Until then the bootloader returns to the previous image on the
/// next reset. Harmless to call when nothing is on probation.
pub fn confirm_running(partition: EspDefaultNvsPartition) {
    match EspOta::new().and_then(|mut ota| ota.mark_running_slot_valid()) {
        Ok(()) => info!("ota: running image {} confirmed", firmware_version()),
        Err(e) => warn!("ota: could not confirm the running image: {e:?}"),
    }

    // The trial is over: this version is now simply what runs here.
    if let Ok(mut nvs) = open(partition) {
        if nvs.get_u64(PENDING_KEY).ok().flatten() == Some(firmware_version()) {
            let _ = nvs.remove(PENDING_KEY);
        }
    }
}

fn open(partition: EspDefaultNvsPartition) -> Result<EspNvs<NvsDefault>> {
    Ok(EspNvs::new(partition, crate::settings::NAMESPACE, true)?)
}

fn verify_signature(digest: &[u8; 32], signature: &[u8; 64]) -> Result<()> {
    let key = PublicKey::from_slice(PUBLIC_KEY).map_err(|e| anyhow!("bad embedded key: {e}"))?;
    let signature = Signature::from_slice(signature).map_err(|e| anyhow!("bad signature: {e}"))?;
    key.verify(digest, &signature)
        .map_err(|_| anyhow!("ota: signature does not verify; refusing the update"))
}

fn download_into_inactive_slot(url: &str, manifest: &Manifest) -> Result<()> {
    let mut client = crate::claim::http_client(Duration::from_secs(30))?;
    let mut response = client.get(url)?.submit()?;
    if response.status() != 200 {
        bail!("ota: image download answered {}", response.status());
    }

    let mut ota = EspOta::new()?;
    let mut update = ota.initiate_update()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut written = 0usize;

    let result: Result<()> = (|| {
        loop {
            let n = response.read(&mut buf).map_err(|e| anyhow!("ota: read failed: {e:?}"))?;
            if n == 0 {
                break;
            }
            written += n;
            if written > manifest.size {
                bail!("ota: image is larger than the manifest says");
            }
            hasher.update(&buf[..n]);
            update.write(&buf[..n])?;
        }

        if written != manifest.size {
            bail!("ota: got {written} bytes, manifest says {}", manifest.size);
        }
        let digest: [u8; 32] = hasher.finalize().into();
        if digest != manifest.sha256 {
            bail!("ota: image digest does not match the signed manifest");
        }
        Ok(())
    })();

    match result {
        // Only now does the bootloader learn about the new slot.
        Ok(()) => update.complete().context("ota: finalising the slot"),
        Err(e) => {
            let _ = update.abort();
            Err(e)
        }
    }
}

/// GET a small document. None on 404, so "nothing published" is not an error.
fn fetch_small(url: &str) -> Result<Option<String>> {
    let mut client = crate::claim::http_client(Duration::from_secs(15))?;
    let mut response = client.get(url)?.submit()?;

    match response.status() {
        200 => {}
        404 => return Ok(None),
        status => bail!("ota: {url} answered {status}"),
    }

    let mut buf = vec![0u8; MAX_MANIFEST];
    let mut len = 0;
    while len < buf.len() {
        match response.read(&mut buf[len..]).map_err(|e| anyhow!("{e:?}"))? {
            0 => break,
            n => len += n,
        }
    }
    Ok(Some(String::from_utf8_lossy(&buf[..len]).into_owned()))
}

fn parse_manifest(body: &str) -> Result<Manifest> {
    let field = |key: &str| {
        crate::claim::json_string(body, key).ok_or_else(|| anyhow!("ota: manifest has no {key}"))
    };
    Ok(Manifest {
        version: json_u64(body, "version").ok_or_else(|| anyhow!("ota: manifest has no version"))?,
        size: json_u64(body, "size").ok_or_else(|| anyhow!("ota: manifest has no size"))? as usize,
        sha256: unhex(&field("sha256")?)?,
        signature: unhex(&field("signature")?)?,
        image: {
            let name = field("image")?;
            // A name, not a path: the manifest must not steer the download
            // anywhere but the firmware directory.
            if name.is_empty() || name.contains('/') || name.contains("..") {
                bail!("ota: refusing image name {name:?}");
            }
            name
        },
    })
}

fn json_u64(body: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\"");
    let after = &body[body.find(&needle)? + needle.len()..];
    let after = after[after.find(':')? + 1..].trim_start();
    let end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
    after[..end].parse().ok()
}

fn unhex<const N: usize>(text: &str) -> Result<[u8; N]> {
    if text.len() != N * 2 {
        bail!("ota: expected {} hex digits, got {}", N * 2, text.len());
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow!("ota: bad hex"))?;
    }
    Ok(out)
}
