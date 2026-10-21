#!/bin/bash
# Build the firmware for the ESP32-C5.
#
#   tools/build-c5.sh [cargo build args...]
#
# Same source as the S3 build; chip differences are #[cfg(esp32c5)]. The C5
# is RISC-V, so it builds with stock nightly Rust instead of the Xtensa
# toolchain. ESP-IDF 5.5 comes from .cargo/config.toml, as for the S3.
# Output: target-c5/riscv32imac-esp-espidf/release/bentoproxy-esp32
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO"

export MCU=esp32c5
export ESP_IDF_SDKCONFIG_DEFAULTS="$REPO/sdkconfig.defaults;$REPO/sdkconfig.c5"
export CARGO_TARGET_DIR="$REPO/target-c5"
# The C5 has one core and runs out of CPU before memory: optimise the Rust
# code for speed rather than the size the S3 build uses.
export CARGO_PROFILE_RELEASE_OPT_LEVEL=${CARGO_PROFILE_RELEASE_OPT_LEVEL:-3}

cargo +nightly build --release --target riscv32imac-esp-espidf "$@"
