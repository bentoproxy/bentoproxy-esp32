# Secure boot and flash encryption

Signed OTA (`src/ota.rs`) stops anyone from pushing firmware *over the network*.
It does not stop someone holding the board: over USB they can flash anything,
or read the flash and take the node's device token out of NVS. Secure Boot V2
and flash encryption close that, using eFuses in the ESP32-S3.

**eFuses can only ever be burned, never cleared.** A mistake bricks the board
or locks it to a key. Practise on a spare board, never on one you need.

## What gets turned on

| | Effect | Permanent |
|---|---|---|
| Secure Boot V2 (RSA-3072) | ROM boots only a bootloader signed with our key; bootloader boots only signed apps; OTA refuses unsigned images | Yes. The key digest is burned into the chip |
| Flash encryption, development mode | Flash contents are AES-XTS encrypted with a key generated on the chip that never leaves it | Yes, but the chip can still be reflashed over USB with encrypted writes |
| UART/USB download mode | Left **on** (`CONFIG_SECURE_INSECURE_ALLOW_DL_MODE`) so a bad image can be recovered | Turning it off later is permanent |

Release mode, which also disables plaintext flashing and JTAG, is the next step
once the process has run on real units. It is a one-line change in
`sdkconfig.secure` and makes OTA the only way to update the unit.

## Files

- `sdkconfig.secure`: overlay on `sdkconfig.defaults`
- `partitions-secure.csv`: the signed bootloader is 44 KB, more than the 32 KB
  before the usual table at 0x8000, so the table moves to 0x10000. App slots
  are unchanged.
- `tools/build-secure.sh`: builds into `target-secure/`, signs the app, and
  checks both signatures. It never touches a board.
- `tools/enable-secure-boot.sh <port> <mac>`: flashes one board, guarded:
  the MAC must match the chip, the chip must not be secured already, and the
  operator types the MAC again. The eFuses are burned by the bootloader on its
  first boot, about a minute after flashing. Don't unplug the board during it.

## The keys: lose them and the fleet is frozen

| Key | Where | Used for |
|---|---|---|
| `~/.config/bentoproxy/secure-boot-signing.pem` | release machine only | signing bootloader and app images for secure units |
| `~/.config/bentoproxy/firmware-signing.key` | release machine only | the Ed25519 OTA manifest signature |

Back up both offline (for example, an encrypted USB stick plus a password
manager). If the secure boot key is lost, every secured unit keeps running
its current firmware forever: no OTA, no USB reflash. If it leaks, an attacker
holding a unit can run their own firmware on it.

Secure Boot V2 lets a chip trust up to three keys. To prepare for rotation,
burn a second key digest at enable time and keep that key offline.

## OTA with secure units

- Secure units need images from `tools/build-secure.sh`, because the app
  compiles in the partition table offset. An image from the normal build
  would not find its partitions. Publish them on a separate manifest, for
  example `firmware/secure/manifest.json`, and point secure builds at that.
  Not built yet: there are no secure units.
- The Ed25519 manifest check still runs first. After that,
  `esp_ota_end` also checks the Secure Boot signature, so an image needs both.
- Rollback works the same. The previous slot is still signed and valid.

## Not covered yet

- **NVS encryption.** Flash encryption doesn't cover NVS, so the device
  token in it can still be read from flash. Encrypt NVS with an HMAC-derived
  key: `CONFIG_NVS_ENCRYPTION` plus `CONFIG_NVS_SEC_KEY_PROTECT_USING_HMAC`.
  This uses one more eFuse key block. Do it before shipping units to people.
- **Release mode and disabling JTAG,** as above.
- **Manufacturing.** Run `enable-secure-boot.sh` per unit at flashing time.
  At volume, burn the eFuses with `espefuse` from a host-generated key so
  the first boot doesn't take a minute.
