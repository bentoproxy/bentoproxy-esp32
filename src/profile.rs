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
// The write path split three ways: building and masking the frame, the TLS
// call itself (encryption plus copying into lwIP), and waiting for the socket
// to accept more. "write" alone could not tell work from waiting.
static BUILD_MICROS: AtomicU32 = AtomicU32::new(0);
static TLS_MICROS: AtomicU32 = AtomicU32::new(0);
static WAIT_MICROS: AtomicU32 = AtomicU32::new(0);

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

pub fn build_done(started: Instant) {
    BUILD_MICROS.fetch_add(started.elapsed().as_micros() as u32, Ordering::Relaxed);
}

pub fn tls_call_done(started: Instant) {
    TLS_MICROS.fetch_add(started.elapsed().as_micros() as u32, Ordering::Relaxed);
}

pub fn wait_done(started: Instant) {
    WAIT_MICROS.fetch_add(started.elapsed().as_micros() as u32, Ordering::Relaxed);
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
    let build_ms = BUILD_MICROS.swap(0, Ordering::Relaxed) / 1000;
    let tls_ms = TLS_MICROS.swap(0, Ordering::Relaxed) / 1000;
    let wait_ms = WAIT_MICROS.swap(0, Ordering::Relaxed) / 1000;

    let window_ms = (window_secs * 1000.0).max(1.0);
    let avg_read = if reads > 0 { read_bytes / reads } else { 0 };

    format!(
        "profile: write {write_ms}ms ({:.0}%, {writes} frames, {stalls} stalls \
         = build {build_ms} + tls {tls_ms} + wait {wait_ms}ms) · \
         read {read_ms}ms ({:.0}%, {reads} reads, avg {avg_read}B) · {sleeps} idle sleeps",
        write_ms as f32 * 100.0 / window_ms,
        read_ms as f32 * 100.0 / window_ms,
    )
}

/// CPU share of each task since the previous call, from FreeRTOS run-time
/// counters. Percentages are of one core, so two busy cores sum to 200%;
/// IDLE0 and IDLE1 are what each core has left.
pub fn task_report() -> String {
    use std::collections::HashMap;
    use std::sync::Mutex;

    static PREVIOUS: Mutex<Option<(u32, HashMap<String, u32>)>> = Mutex::new(None);

    let mut now = HashMap::new();
    let mut total: u32 = 0;
    unsafe {
        let capacity = esp_idf_sys::uxTaskGetNumberOfTasks() as usize + 4;
        let mut tasks: Vec<esp_idf_sys::TaskStatus_t> = Vec::with_capacity(capacity);
        let got = esp_idf_sys::uxTaskGetSystemState(tasks.as_mut_ptr(), capacity as _, &mut total);
        tasks.set_len(got as usize);
        for task in &tasks {
            let name = std::ffi::CStr::from_ptr(task.pcTaskName)
                .to_string_lossy()
                .into_owned();
            now.insert(name, task.ulRunTimeCounter);
        }
    }

    let Ok(mut previous) = PREVIOUS.lock() else {
        return String::new();
    };

    let report = match previous.as_ref() {
        Some((previous_total, previous_tasks)) => {
            // Microsecond counters wrap every ~71 minutes; wrapping_sub copes
            // with one wrap inside a window.
            let elapsed = total.wrapping_sub(*previous_total).max(1) as f32;
            let mut rows: Vec<(String, f32)> = now
                .iter()
                .map(|(name, &counter)| {
                    let before = previous_tasks.get(name).copied().unwrap_or(0);
                    (name.clone(), counter.wrapping_sub(before) as f32 * 100.0 / elapsed)
                })
                .filter(|(_, share)| *share >= 1.0)
                .collect();
            rows.sort_by(|a, b| b.1.total_cmp(&a.1));
            let rows: Vec<String> = rows.iter().map(|(n, p)| format!("{n} {p:.0}%")).collect();
            format!("cpu: {}", rows.join(" · "))
        }
        None => "cpu: first sample".to_string(),
    };

    *previous = Some((total, now));
    report
}
