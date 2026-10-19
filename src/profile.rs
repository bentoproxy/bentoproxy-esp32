//! Where the relay loop spends its time.
//!
//! Throughput through the node was about a fifth of what its network allows,
//! and guessing at the cause did not move it. These counters split each
//! reporting window into time spent writing to the orchestrator, reading from
//! targets and sleeping, so a change can be aimed at what actually dominates.
//!
//! Plain atomics, read and reset by the periodic report: cheap enough to stay
//! on in production.

use std::sync::atomic::{AtomicU32, Ordering};

// Xtensa has no 64-bit atomics. 32 bits is ample for one reporting window:
// even microseconds only reach ~15 million in 15 seconds.
use std::time::Instant;

static WRITE_MICROS: AtomicU32 = AtomicU32::new(0);
static WRITE_CALLS: AtomicU32 = AtomicU32::new(0);
/// Times a write found the socket full and had to wait.
static WRITE_STALLS: AtomicU32 = AtomicU32::new(0);
static READ_MICROS: AtomicU32 = AtomicU32::new(0);
static READ_BYTES: AtomicU32 = AtomicU32::new(0);
static READ_CALLS: AtomicU32 = AtomicU32::new(0);
static IDLE_SLEEPS: AtomicU32 = AtomicU32::new(0);

pub fn write_done(started: Instant) {
    WRITE_MICROS.fetch_add(started.elapsed().as_micros() as u32, Ordering::Relaxed);
    WRITE_CALLS.fetch_add(1, Ordering::Relaxed);
}

pub fn write_stalled() {
    WRITE_STALLS.fetch_add(1, Ordering::Relaxed);
}

pub fn read_done(started: Instant, bytes: usize) {
    READ_MICROS.fetch_add(started.elapsed().as_micros() as u32, Ordering::Relaxed);
    READ_BYTES.fetch_add(bytes as u32, Ordering::Relaxed);
    READ_CALLS.fetch_add(1, Ordering::Relaxed);
}

pub fn idle_sleep() {
    IDLE_SLEEPS.fetch_add(1, Ordering::Relaxed);
}

/// One line summarising the window since the last call, then reset.
pub fn take_report(window_secs: f32) -> String {
    let write_ms = WRITE_MICROS.swap(0, Ordering::Relaxed) / 1000;
    let writes = WRITE_CALLS.swap(0, Ordering::Relaxed);
    let stalls = WRITE_STALLS.swap(0, Ordering::Relaxed);
    let read_ms = READ_MICROS.swap(0, Ordering::Relaxed) / 1000;
    let read_bytes = READ_BYTES.swap(0, Ordering::Relaxed);
    let reads = READ_CALLS.swap(0, Ordering::Relaxed);
    let sleeps = IDLE_SLEEPS.swap(0, Ordering::Relaxed);

    let window_ms = (window_secs * 1000.0).max(1.0);
    let avg_read = if reads > 0 { read_bytes / reads } else { 0 };

    format!(
        "profile: write {write_ms}ms ({:.0}%, {writes} frames, {stalls} stalls) · \
         read {read_ms}ms ({:.0}%, {reads} reads, avg {avg_read}B) · {sleeps} idle sleeps",
        write_ms as f32 * 100.0 / window_ms,
        read_ms as f32 * 100.0 / window_ms,
    )
}
