//! Raw network capacity, measured from the node with no relay involved.
//!
//! A relay re-sends every byte it downloads, so its throughput is bounded by
//! whichever direction its network allows less of. Measuring both directly
//! separates "the firmware is slow" from "the network is slow" — the two look
//! identical from the orchestrator's side.
//!
//! Built only with `--features netdiag`. It runs once at boot, after WiFi is
//! up, and logs results over serial; production firmware never sends this
//! traffic.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use log::{info, warn};

const HOST: &str = "speed.cloudflare.com";
const BYTES: usize = 1024 * 1024;
const ROUNDS: usize = 3;
const TIMEOUT: Duration = Duration::from_secs(30);

pub fn run() {
    info!("netdiag: measuring raw capacity against {HOST} ({} KB per transfer)", BYTES / 1024);

    for round in 1..=ROUNDS {
        match download() {
            Ok(rate) => info!("netdiag: round {round} download {:>5} KB/s", rate / 1024),
            Err(e) => warn!("netdiag: round {round} download failed: {e}"),
        }
        match upload() {
            Ok(rate) => info!("netdiag: round {round} upload   {:>5} KB/s", rate / 1024),
            Err(e) => warn!("netdiag: round {round} upload failed: {e}"),
        }
    }

    info!("netdiag: done");
}

fn connect() -> std::io::Result<TcpStream> {
    let stream = TcpStream::connect((HOST, 80))?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    Ok(stream)
}

/// Bytes per second for a plain download, timed from the first byte.
fn download() -> std::io::Result<usize> {
    let mut stream = connect()?;
    write!(
        stream,
        "GET /__down?bytes={BYTES} HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"
    )?;

    let mut buf = vec![0u8; 8192];
    let mut total = 0usize;
    let mut started: Option<Instant> = None;

    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        started.get_or_insert_with(Instant::now);
        total += n;
    }

    rate(total, started)
}

/// Bytes per second for a plain upload, timed over the body.
fn upload() -> std::io::Result<usize> {
    let mut stream = connect()?;
    write!(
        stream,
        "POST /__up HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/octet-stream\r\n\
         Content-Length: {BYTES}\r\nConnection: close\r\n\r\n"
    )?;

    let chunk = vec![0u8; 8192];
    let started = Instant::now();
    let mut sent = 0usize;
    while sent < BYTES {
        let n = (BYTES - sent).min(chunk.len());
        stream.write_all(&chunk[..n])?;
        sent += n;
    }
    stream.flush()?;

    // The upload is not done until the server has it all; its response is
    // the acknowledgement.
    let mut response = [0u8; 256];
    let _ = stream.read(&mut response)?;

    rate(sent, Some(started))
}

fn rate(bytes: usize, started: Option<Instant>) -> std::io::Result<usize> {
    let elapsed = started
        .ok_or_else(|| std::io::Error::other("no data received"))?
        .elapsed()
        .as_millis()
        .max(1) as usize;
    Ok(bytes * 1000 / elapsed)
}
