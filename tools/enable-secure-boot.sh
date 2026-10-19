#!/bin/bash
# Turn on Secure Boot V2 and flash encryption on ONE board. IRREVERSIBLE.
#
#   tools/enable-secure-boot.sh <port> <mac-address>
#
# Flashes the output of tools/build-secure.sh. Nothing is burned by this
# script itself: the signed bootloader burns the eFuses on its first boot,
# which happens when the board resets at the end. From then on the board
# runs only images signed with the secure boot key, for the rest of its life.
# Lose the key and the board can never be updated again.
#
# Guards, all of which must pass:
#   - the MAC given on the command line must match the chip on <port>,
#     so a script pointed at the wrong USB port stops
#   - the chip must not already have secure boot or flash encryption
#   - the operator must type the MAC again at the prompt
#
# Read docs/secure-boot.md first.
set -euo pipefail

PORT=${1:?usage: $0 <port> <mac-address>}
EXPECTED_MAC=$(echo "${2:?usage: $0 <port> <mac-address>}" | tr 'A-F' 'a-f')

REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT=$REPO/target-secure/out
KEY=${BENTO_SECURE_BOOT_KEY:-$HOME/.config/bentoproxy/secure-boot-signing.pem}
PY=$(ls "$REPO"/.embuild/espressif/python_env/*/bin/python | head -1)

for f in bootloader.bin partitions.bin app-signed.bin; do
    [ -f "$OUT/$f" ] || { echo "missing $OUT/$f; run tools/build-secure.sh" >&2; exit 1; }
done
# The images must carry signatures from the key we hold, or the board would
# lock itself to a key nobody has.
"$PY" -m espsecure verify_signature --version 2 --keyfile "$KEY" "$OUT/bootloader.bin" >/dev/null
"$PY" -m espsecure verify_signature --version 2 --keyfile "$KEY" "$OUT/app-signed.bin" >/dev/null

# Anything still holding the port makes the flash fail half way.
pkill -f "cat $PORT" 2>/dev/null || true

SUMMARY=$("$PY" -m espefuse --chip esp32s3 --port "$PORT" summary 2>&1)
MAC=$(echo "$SUMMARY" | grep -Eo '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1)
[ "$MAC" = "$EXPECTED_MAC" ] || { echo "chip on $PORT is $MAC, not $EXPECTED_MAC; stopping" >&2; exit 1; }

if ! echo "$SUMMARY" | grep -E '^SECURE_BOOT_EN ' | grep -q '= False'; then
    echo "secure boot is already enabled on $MAC; stopping" >&2; exit 1
fi
if ! echo "$SUMMARY" | grep -E 'SPI_BOOT_CRYPT_CNT' | grep -q '(0b000)'; then
    echo "flash encryption is already enabled on $MAC; stopping" >&2; exit 1
fi

cat <<WARN

  About to lock board $MAC to:
    secure boot key  $KEY
    key digest       $("$PY" -m espsecure digest_sbv2_public_key --keyfile "$KEY" --output /dev/stdout 2>/dev/null | xxd -p -c 64 | head -1)

  On its next boot it will PERMANENTLY:
    - accept only firmware signed with that key
    - encrypt its flash with a key that never leaves the chip
  There is no undo. Back up the key before continuing.

WARN
read -r -p "Type the board's MAC address to continue: " CONFIRM
[ "$(echo "$CONFIRM" | tr 'A-F' 'a-f')" = "$EXPECTED_MAC" ] || { echo "not confirmed; nothing written"; exit 1; }

# Plaintext writes: the bootloader encrypts everything in place on first boot.
# otadata is erased so the board starts from slot ota_0, where the app goes.
"$PY" -m esptool --chip esp32s3 --port "$PORT" --baud 921600 \
    write_flash --flash_mode dio --flash_size 16MB \
    0x0 "$OUT/bootloader.bin" \
    0x10000 "$OUT/partitions.bin" \
    0x20000 "$OUT/app-signed.bin"
"$PY" -m esptool --chip esp32s3 --port "$PORT" erase_region 0x17000 0x2000

echo
echo "Flashed. The first boot burns the eFuses and encrypts the flash; it takes"
echo "about a minute and must not be interrupted by unplugging the board."
echo "Watch it with:  stty -f $PORT 115200 raw; cat $PORT"
