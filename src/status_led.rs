//! The node's one LED, telling its owner whether it needs them.
//!
//! Every board has a single colour (blue on the S3, yellow on the XIAO
//! ESP32-C5), so states differ by rhythm:
//!
//! | LED                            | state                                     |
//! |--------------------------------|-------------------------------------------|
//! | slow blink, once a second      | needs WiFi: the setup network is open     |
//! | double blink                   | on WiFi, waiting to be claimed            |
//! | fast blink                     | connecting, or the server is unreachable  |
//! | solid for a minute, then off   | online                                    |
//! | brief flickers                 | relaying traffic                          |
//!
//! Blinking always means "look at me". A working node is dark apart from
//! traffic: it sits in someone's home for years, and a permanent light is
//! what people end up taping over.
//!
//! A thread owns the pin and draws the pattern; the rest of the firmware only
//! reports its state and its traffic, which costs an atomic store.

use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use esp_idf_hal::gpio::{Output, PinDriver};
use log::warn;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    Off = 0,
    Setup = 1,
    AwaitingClaim = 2,
    Connecting = 3,
    Online = 4,
}

static STATE: AtomicU8 = AtomicU8::new(State::Off as u8);
/// Bumped whenever bytes are relayed; the LED thread watches it change.
static ACTIVITY: AtomicU32 = AtomicU32::new(0);

/// Pattern resolution. Also the shortest flicker.
const TICK: Duration = Duration::from_millis(50);
/// How long a node shows solid after coming online, as confirmation.
const ONLINE_SOLID: Duration = Duration::from_secs(60);

/// The board's LED pin and which level lights it.
pub struct Led {
    pub pin: PinDriver<'static, Output>,
    pub lit_when_high: bool,
}

impl Led {
    fn set(&mut self, lit: bool) {
        let _ = if lit == self.lit_when_high {
            self.pin.set_high()
        } else {
            self.pin.set_low()
        };
    }
}

pub fn set(state: State) {
    STATE.store(state as u8, Ordering::Relaxed);
}

/// Bytes moved: shown as a flicker once the node is online.
pub fn activity() {
    ACTIVITY.fetch_add(1, Ordering::Relaxed);
}

/// Take over the LED. Patterns follow `set` from here on.
pub fn start(mut led: Led) {
    led.set(false);
    let spawned = thread::Builder::new()
        .name("status-led".into())
        .stack_size(3072)
        .spawn(move || {
            let mut state = u8::MAX;
            let mut entered = Instant::now();
            let mut seen_activity = ACTIVITY.load(Ordering::Relaxed);
            let mut lit_now = false;
            let mut tick: u32 = 0;

            loop {
                let current = STATE.load(Ordering::Relaxed);
                if current != state {
                    state = current;
                    entered = Instant::now();
                }
                let in_state = entered.elapsed();
                let ms = in_state.as_millis() as u64;

                let activity = ACTIVITY.load(Ordering::Relaxed);
                let busy = activity != seen_activity;
                seen_activity = activity;

                let lit = match state {
                    s if s == State::Setup as u8 => ms % 1000 < 500,
                    s if s == State::AwaitingClaim as u8 => {
                        matches!(ms % 1200, 0..=149 | 300..=449)
                    }
                    s if s == State::Connecting as u8 => ms % 200 < 100,
                    s if s == State::Online as u8 => {
                        // Lit on every other busy tick, so steady traffic
                        // reads as a flicker rather than a solid light.
                        in_state < ONLINE_SOLID || (busy && tick % 2 == 0)
                    }
                    _ => false,
                };

                if lit != lit_now {
                    led.set(lit);
                    lit_now = lit;
                }
                tick = tick.wrapping_add(1);
                thread::sleep(TICK);
            }
        });
    if let Err(e) = spawned {
        warn!("status LED unavailable: {e:?}");
    }
}
