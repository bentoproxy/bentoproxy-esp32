//! Firmware signing for over-the-air updates.
//!
//! Nodes accept an update only if its SHA-256 digest carries an Ed25519
//! signature from the release key. The private key never leaves the release
//! machine; nodes embed only the public key.
//!
//!   fwsign keygen <secret-key-file> <public-key-file>
//!   fwsign sign <secret-key-file> <image.bin> <version> <image-url-name>
//!
//! `sign` prints the manifest a node fetches to decide whether to update.

use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_compact::{KeyPair, Noise, SecretKey, Seed};
use sha2::{Digest, Sha256};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("keygen") if args.len() == 3 => keygen(&args[1], &args[2]),
        Some("sign") if args.len() == 5 => sign(&args[1], &args[2], &args[3], &args[4]),
        _ => bail!(
            "usage:\n  fwsign keygen <secret-key-file> <public-key-file>\n  \
             fwsign sign <secret-key-file> <image.bin> <version> <image-url-name>"
        ),
    }
}

fn keygen(secret_path: &str, public_path: &str) -> Result<()> {
    if Path::new(secret_path).exists() {
        // Overwriting the key would orphan every node that trusts the old one.
        bail!("{secret_path} already exists; refusing to overwrite a signing key");
    }

    let pair = KeyPair::from_seed(Seed::generate());
    fs::write(secret_path, pair.sk.as_ref()).context("writing the secret key")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(secret_path, fs::Permissions::from_mode(0o600))?;
    }
    fs::write(public_path, pair.pk.as_ref()).context("writing the public key")?;

    eprintln!("secret key: {secret_path} (keep it off any shared machine, and back it up:");
    eprintln!("  nodes can only ever be updated with this key)");
    eprintln!("public key: {public_path} (embed in the firmware)");
    Ok(())
}

fn sign(secret_path: &str, image_path: &str, version: &str, image_name: &str) -> Result<()> {
    let secret = fs::read(secret_path).context("reading the secret key")?;
    let sk = SecretKey::from_slice(&secret).map_err(|e| anyhow!("bad secret key: {e}"))?;

    let version: u64 = version.parse().context("version must be an integer")?;
    let image = fs::read(image_path).context("reading the image")?;
    let digest = Sha256::digest(&image);

    // Sign the digest, not the image: the node streams a 1MB+ image straight
    // to flash and cannot hold it in memory, but it can hash as it goes.
    let signature = sk.sign(digest, Some(Noise::generate()));

    // Check the round trip before publishing anything.
    sk.public_key()
        .verify(digest, &signature)
        .map_err(|e| anyhow!("signature does not verify: {e}"))?;

    println!(
        "{{\"version\":{version},\"size\":{},\"sha256\":\"{}\",\"signature\":\"{}\",\"image\":\"{image_name}\"}}",
        image.len(),
        hex(&digest),
        hex(signature.as_ref()),
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
