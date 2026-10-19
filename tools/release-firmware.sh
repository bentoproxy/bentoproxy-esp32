#!/bin/bash
# Build, sign and publish a firmware release for over-the-air updates.
#
#   tools/release-firmware.sh [version]
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
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
KEY=${BENTO_SIGNING_KEY:-$HOME/.config/bentoproxy/firmware-signing.key}
SERVER=${BENTO_SERVER:-lukas@65.109.22.247}
PORT=${BENTO_SSH_PORT:-2222}
REMOTE_DIR=${BENTO_FIRMWARE_DIR:-/opt/apps/bentoproxy/firmware}
VERSION=${1:-$(date -u +%Y%m%d%H%M)}
FEATURES=${BENTO_FW_FEATURES:-}

[ -f "$KEY" ] || { echo "signing key not found: $KEY" >&2; exit 1; }
[[ "$VERSION" =~ ^[0-9]+$ ]] || { echo "version must be an integer: $VERSION" >&2; exit 1; }

cd "$REPO"
# shellcheck disable=SC1090
source ~/export-esp.sh

# A release must never carry one person's WiFi or device credentials: every
# node gets those from setup and claiming.
unset ORCHESTRATOR_URL DEVICE_ID DEVICE_TOKEN WIFI_SSID WIFI_PASSWORD

echo "==> building firmware $VERSION"
BENTO_FW_VERSION=$VERSION cargo build --release ${FEATURES:+--features "$FEATURES"}

ELF=target/xtensa-esp32s3-espidf/release/bentoproxy-esp32
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

# An app image, not a merged flash image: OTA replaces only the app slot.
espflash save-image --chip esp32s3 --flash-mode dio --flash-size 16mb "$ELF" "$OUT/app.bin" >/dev/null

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

echo "==> publishing to $SERVER:$REMOTE_DIR"
# Image first, manifest last, and the manifest swapped in atomically: a node
# must never see a manifest whose image is not fully there yet.
scp -q -P "$PORT" "$OUT/$IMAGE" "$SERVER:$REMOTE_DIR/$IMAGE"
scp -q -P "$PORT" "$OUT/manifest.json" "$SERVER:$REMOTE_DIR/manifest.json.tmp"
ssh -p "$PORT" "$SERVER" "mv $REMOTE_DIR/manifest.json.tmp $REMOTE_DIR/manifest.json"

echo "==> released $VERSION"
cat "$OUT/manifest.json"; echo
