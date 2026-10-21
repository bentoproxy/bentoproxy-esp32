//! Waiting for socket activity instead of sleeping and re-polling.
//!
//! Profiling showed the relay asleep ~79% of the time during a transfer while
//! the CPU sat idle: each pass that found its sockets empty slept, and on a
//! 100Hz scheduler every sleep is a whole 10ms tick, however short the request.
//! Data that arrived just after the check waited out the tick, the target's
//! TCP window filled, and the sender stalled. select() wakes the moment any
//! socket is readable and costs nothing while idle.

use std::time::Duration;

/// Descriptor-set capacity. lwIP numbers its sockets from
/// FD_SETSIZE - CONFIG_LWIP_MAX_SOCKETS up to FD_SETSIZE - 1, so they always
/// fall inside the set (16 sockets on the S3, 24 on the C5). `add` refuses
/// anything outside rather than corrupt memory.
const FD_LIMIT: i32 = esp_idf_sys::FD_SETSIZE as i32;

/// A set of descriptors to wait on.
pub struct FdSet {
    set: esp_idf_sys::fd_set,
    max_fd: i32,
}

impl FdSet {
    pub fn new() -> Self {
        Self {
            set: unsafe { std::mem::zeroed() },
            max_fd: -1,
        }
    }

    pub fn add(&mut self, fd: i32) {
        if !(0..FD_LIMIT).contains(&fd) {
            return;
        }
        // newlib's fd_set: an array of 32-bit words, bit (fd % 32) of word
        // (fd / 32), as FD_SET does in C.
        let bits = 8 * std::mem::size_of_val(&self.set.__fds_bits[0]) as i32;
        let word = (fd / bits) as usize;
        self.set.__fds_bits[word] |= 1 << (fd % bits);
        self.max_fd = self.max_fd.max(fd);
    }

    fn is_empty(&self) -> bool {
        self.max_fd < 0
    }
}

/// Block until a descriptor in `read` is readable, one in `write` is
/// writable, or `timeout` passes. Returns early on any activity.
///
/// Errors fall back to sleeping for the timeout: a failed wait must slow the
/// loop down, never spin it.
pub fn wait(mut read: FdSet, mut write: FdSet, timeout: Duration) {
    if read.is_empty() && write.is_empty() {
        std::thread::sleep(timeout);
        return;
    }

    let nfds = read.max_fd.max(write.max_fd) + 1;
    let mut tv = esp_idf_sys::timeval {
        tv_sec: timeout.as_secs() as _,
        tv_usec: timeout.subsec_micros() as _,
    };

    let read_ptr = if read.is_empty() { std::ptr::null_mut() } else { &mut read.set as *mut _ };
    let write_ptr = if write.is_empty() { std::ptr::null_mut() } else { &mut write.set as *mut _ };

    let result = unsafe {
        esp_idf_sys::select(nfds, read_ptr, write_ptr, std::ptr::null_mut(), &mut tv)
    };

    if result < 0 {
        std::thread::sleep(timeout);
    }
}
