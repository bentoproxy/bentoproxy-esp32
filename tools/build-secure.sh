#!/bin/bash
# Build the secure-boot + flash-encryption variant and sign its app image.
#
#   tools/build-secure.sh
#
# Builds only; it never touches a board. Output lands in target-secure/out:
#   bootloader.bin   signed bootloader (burns eFuses on its FIRST boot)
#   partitions.bin   partition table
#   app-signed.bin   app image carrying a Secure Boot V2 signature block
#
# Environment:
#   BENTO_SECURE_BOOT_KEY  RSA-3072 key (~/.config/bentoproxy/secure-boot-signing.pem)
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
KEY=${BENTO_SECURE_BOOT_KEY:-$HOME/.config/bentoproxy/secure-boot-signing.pem}
[ -f "$KEY" ] || { echo "secure boot key not found: $KEY" >&2; exit 1; }

cd "$REPO"
# shellcheck disable=SC1090
source ~/export-esp.sh
unset ORCHESTRATOR_URL DEVICE_ID DEVICE_TOKEN WIFI_SSID WIFI_PASSWORD

TARGET=$REPO/target-secure
OUT=$TARGET/out
mkdir -p "$OUT"

# The key path is machine-specific, so it is added here rather than committed.
OVERLAY=$TARGET/sdkconfig.secure.local
{ cat sdkconfig.secure; echo "CONFIG_SECURE_BOOT_SIGNING_KEY=\"$KEY\""; } > "$OVERLAY"

# Separate target dir: the secure IDF build must never leak into the normal one.
ESP_IDF_SDKCONFIG_DEFAULTS="$REPO/sdkconfig.defaults;$OVERLAY" \
CARGO_TARGET_DIR=$TARGET \
    cargo build --release

ELF=$TARGET/xtensa-esp32s3-espidf/release/bentoproxy-esp32
BUILD=$(ls -dt "$TARGET"/xtensa-esp32s3-espidf/release/build/esp-idf-sys-*/out/build | head -1)

# espflash would otherwise substitute its own unsigned bootloader, which a
# secure-boot chip refuses to run.
cp "$BUILD/bootloader/bootloader.bin" "$OUT/bootloader.bin"
cp "$BUILD/partition_table/partition-table.bin" "$OUT/partitions.bin"

espflash save-image --chip esp32s3 --flash-mode dio --flash-size 16mb "$ELF" "$OUT/app.bin" >/dev/null
PY=$(ls "$REPO"/.embuild/espressif/python_env/*/bin/python | head -1)
"$PY" -m espsecure sign_data --version 2 --keyfile "$KEY" --output "$OUT/app-signed.bin" "$OUT/app.bin"
"$PY" -m espsecure verify_signature --version 2 --keyfile "$KEY" "$OUT/app-signed.bin"
"$PY" -m espsecure verify_signature --version 2 --keyfile "$KEY" "$OUT/bootloader.bin"
rm "$OUT/app.bin"

echo "==> built and signed in $OUT"
