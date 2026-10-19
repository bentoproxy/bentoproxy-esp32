//! Off-loop target connection with a small DNS cache.
//!
//! Resolving and connecting used to happen inline in the main loop, so one
//! slow DNS lookup stalled every other stream and the ping timer with it — on
//! a device whose whole job is relaying, a few seconds of that is enough for
//! the orchestrator to consider the node dead. A worker thread owns connect
//! now; the main loop hands over a request and picks the socket up later.
//!
//! The cache matters more here than on a desktop agent: pages pull in dozens
//! of hosts, and lwIP has no resolver cache of its own worth the name.

use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::time::{Duration, Instant};

use anyhow::Result;
use log::{debug, error, info};

use crate::netfilter;

/// How long a resolved address is reused.
const DNS_TTL: Duration = Duration::from_secs(300);
/// Cached targets. Small: RAM is the scarce resource here, not lookups.
const DNS_MAX_ENTRIES: usize = 32;
/// Giving up beats blocking the worker on an unreachable host.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Worker stack: TLS-free, but getaddrinfo needs more than the 3KB default.
const WORKER_STACK: usize = 8192;

pub struct Request {
    pub stream_id: u32,
    pub host: String,
    pub port: u16,
}

pub enum Outcome {
    /// Connected and switched to non-blocking.
    Connected { stream_id: u32, stream: TcpStream },
    /// Refused, unreachable, or filtered.
    Failed { stream_id: u32 },
}

/// Handle to the connect worker.
pub struct Connector {
    requests: Sender<Request>,
    outcomes: Receiver<Outcome>,
}

impl Connector {
    pub fn spawn() -> Result<Self> {
        let (req_tx, req_rx) = mpsc::channel::<Request>();
        let (out_tx, out_rx) = mpsc::channel::<Outcome>();

        std::thread::Builder::new()
            .stack_size(WORKER_STACK)
            .name("connector".into())
            .spawn(move || worker(req_rx, out_tx))?;

        Ok(Self { requests: req_tx, outcomes: out_rx })
    }

    /// Queue a connection. Returns false if the worker is gone.
    pub fn request(&self, stream_id: u32, host: String, port: u16) -> bool {
        self.requests.send(Request { stream_id, host, port }).is_ok()
    }

    /// Collect whatever finished since the last call.
    pub fn poll(&self) -> Vec<Outcome> {
        let mut done = Vec::new();
        loop {
            match self.outcomes.try_recv() {
                Ok(outcome) => done.push(outcome),
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => return done,
            }
        }
    }
}

fn worker(requests: Receiver<Request>, outcomes: Sender<Outcome>) {
    let mut cache: HashMap<String, (Vec<SocketAddr>, Instant)> = HashMap::new();

    while let Ok(req) = requests.recv() {
        let outcome = match connect(&req, &mut cache) {
            Ok(stream) => {
                info!("stream {} connected to {}:{}", req.stream_id, req.host, req.port);
                Outcome::Connected { stream_id: req.stream_id, stream }
            }
            Err(e) => {
                error!("stream {} to {}:{} failed: {}", req.stream_id, req.host, req.port, e);
                Outcome::Failed { stream_id: req.stream_id }
            }
        };

        if outcomes.send(outcome).is_err() {
            return; // Main loop is gone; so is this connection's purpose.
        }
    }
}

fn connect(
    req: &Request,
    cache: &mut HashMap<String, (Vec<SocketAddr>, Instant)>,
) -> Result<TcpStream> {
    let key = format!("{}:{}", req.host, req.port);

    let addrs = match cache.get(&key) {
        Some((addrs, expires)) if *expires > Instant::now() => {
            debug!("DNS cache hit for {key}");
            addrs.clone()
        }
        _ => {
            let resolved = netfilter::resolve_allowed(&req.host, req.port)?;
            if resolved.is_empty() {
                // Either the name resolves only to LAN addresses, or someone
                // is pointing the node at its own network on purpose.
                anyhow::bail!("all addresses for {key} are blocked");
            }
            store(cache, key.clone(), resolved.clone());
            resolved
        }
    };

    let mut last_err = None;
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) {
            Ok(stream) => {
                stream.set_nonblocking(true)?;
                return Ok(stream);
            }
            Err(e) => last_err = Some(e),
        }
    }

    Err(last_err
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("no addresses for {key}")))
}

fn store(cache: &mut HashMap<String, (Vec<SocketAddr>, Instant)>, key: String, addrs: Vec<SocketAddr>) {
    if cache.len() >= DNS_MAX_ENTRIES {
        let now = Instant::now();
        cache.retain(|_, (_, expires)| *expires > now);

        // Still full: drop one entry rather than grow without bound.
        if cache.len() >= DNS_MAX_ENTRIES {
            if let Some(victim) = cache.keys().next().cloned() {
                cache.remove(&victim);
            }
        }
    }

    cache.insert(key, (addrs, Instant::now() + DNS_TTL));
}
