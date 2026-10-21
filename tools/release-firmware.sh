#!/bin/bash
# Build, sign and publish a firmware release for over-the-air updates.
#
#   tools/release-firmware.sh [version]
#
# Each chip has its own channel, firmware/<chip>/, because an image only runs
# on the chip it was built for. BENTO_FW_CHIP picks the chip (esp32s3).
#
# The version defaults to the UTC time (YYYYMMDDHHMM), which only ever grows,
# so every release supersedes the last. Nodes check at boot and every 12h.
#
# Environment:
#   BENTO_SIGNING_KEY    release key   (~/.config/bentoproxy/firmware-signing.key)
#   BENTO_SERVER         ssh target    (lukas@65.109.22.247)
#   BENTO_SSH_PORT       ssh port      (2222)
#   BENTO_FIRMWARE_DIR   remote dir    (/opt/apps/bentoproxy/firmware)
#   BENTO_FW_FEATURES    cargo features for test releases (none)
#   BENTO_FW_CHIP        esp32s3 or esp32c5 (esp32s3)
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
KEY=${BENTO_SIGNING_KEY:-$HOME/.config/bentoproxy/firmware-signing.key}
SERVER=${BENTO_SERVER:-lukas@65.109.22.247}
PORT=${BENTO_SSH_PORT:-2222}
REMOTE_DIR=${BENTO_FIRMWARE_DIR:-/opt/apps/bentoproxy/firmware}
VERSION=${1:-$(date -u +%Y%m%d%H%M)}
FEATURES=${BENTO_FW_FEATURES:-}
CHIP=${BENTO_FW_CHIP:-esp32s3}

case "$CHIP" in
    esp32s3) ELF=target/xtensa-esp32s3-espidf/release/bentoproxy-esp32; FLASH=16mb ;;
    esp32c5) ELF=target-c5/riscv32imac-esp-espidf/release/bentoproxy-esp32; FLASH=8mb ;;
    *) echo "unknown chip: $CHIP" >&2; exit 1 ;;
esac

[ -f "$KEY" ] || { echo "signing key not found: $KEY" >&2; exit 1; }
[[ "$VERSION" =~ ^[0-9]+$ ]] || { echo "version must be an integer: $VERSION" >&2; exit 1; }

cd "$REPO"
# shellcheck disable=SC1090
source ~/export-esp.sh

# A release must never carry one person's WiFi or device credentials: every
# node gets those from setup and claiming.
unset ORCHESTRATOR_URL DEVICE_ID DEVICE_TOKEN WIFI_SSID WIFI_PASSWORD

echo "==> building $CHIP firmware $VERSION"
if [ "$CHIP" = esp32c5 ]; then
    BENTO_FW_VERSION=$VERSION tools/build-c5.sh ${FEATURES:+--features "$FEATURES"}
else
    BENTO_FW_VERSION=$VERSION cargo build --release ${FEATURES:+--features "$FEATURES"}
fi

OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

# An app image, not a merged flash image: OTA replaces only the app slot.
espflash save-image --chip "$CHIP" --flash-mode dio --flash-size "$FLASH" "$ELF" "$OUT/app.bin" >/dev/null

# Content-addressed name. Cloudflare caches .bin files for hours, so a name
# must never be reused for different bytes: a re-published release would be
# served stale. (Nodes would reject it on the hash, but stay stuck behind the
# cache.) Unique names also let the cache serve images to a whole fleet.
DIGEST=$(shasum -a 256 "$OUT/app.bin" | cut -c1-12)
IMAGE=image-$VERSION-$DIGEST.bin
mv "$OUT/app.bin" "$OUT/$IMAGE"
SIZE=$(stat -f %z "$OUT/$IMAGE" 2>/dev/null || stat -c %s "$OUT/$IMAGE")
(( SIZE < 3 * 1024 * 1024 )) || { echo "image is $SIZE bytes; it must fit a 3MB slot" >&2; exit 1; }

echo "==> signing ($SIZE bytes)"
(cd / && cargo +stable build --quiet --release --manifest-path "$REPO/tools/fwsign/Cargo.toml")
"$REPO/tools/fwsign/target/release/fwsign" sign "$KEY" "$OUT/$IMAGE" "$VERSION" "$IMAGE" > "$OUT/manifest.json"

publish() { # remote directory
    echo "==> publishing to $SERVER:$1"
    ssh -p "$PORT" "$SERVER" "mkdir -p $1"
    # Image first, manifest last, and the manifest swapped in atomically: a
    # node must never see a manifest whose image is not fully there yet.
    scp -q -P "$PORT" "$OUT/$IMAGE" "$SERVER:$1/$IMAGE"
    scp -q -P "$PORT" "$OUT/manifest.json" "$SERVER:$1/manifest.json.tmp"
    ssh -p "$PORT" "$SERVER" "mv $1/manifest.json.tmp $1/manifest.json"
}

publish "$REMOTE_DIR/$CHIP"
# S3 firmware from before per-chip channels reads the top-level manifest;
# keep it current so those nodes still reach the release that moves them.
if [ "$CHIP" = esp32s3 ]; then
    publish "$REMOTE_DIR"
fi

echo "==> released $VERSION"
cat "$OUT/manifest.json"; echo
