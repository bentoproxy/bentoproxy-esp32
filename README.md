# BentoProxy ESP32 Node

ESP32 firmware for running a BentoProxy residential proxy node. Earn money by sharing your home internet connection.

## Hardware Requirements

- **ESP32-S3** (recommended) or ESP32
- 4MB+ Flash
- WiFi connectivity
- USB-C cable for programming

## Features

- ✅ WiFi connectivity
- ✅ WebSocket client with TLS
- ✅ Binary protocol (see [bentoproxy-protocol](../protocol/))
- ✅ TCP stream multiplexing (up to 8 concurrent connections)
- ✅ Automatic reconnection
- ✅ Low power consumption

## Setup

### 1. Install Rust ESP Toolchain

```bash
# Install espup
cargo install espup

# Install ESP Rust toolchain
espup install

# Source the environment
. $HOME/export-esp.sh
```

### 2. Install espflash

```bash
cargo install espflash
```

### 3. Configure Environment

Create a `.env` file in this directory:

```bash
ORCHESTRATOR_URL=wss://bentoproxy.com:8443/ws/device
DEVICE_ID=your-device-id
DEVICE_TOKEN=your-secret-token
WIFI_SSID=YourWiFiNetwork
WIFI_PASSWORD=YourWiFiPassword
```

Get your device ID and token from the BentoProxy dashboard at https://bentoproxy.com/dashboard

### 4. Build and Flash

```bash
# Build the firmware
cargo build --release

# Flash to ESP32 (with serial monitor)
cargo run --release

# Or flash without monitor
espflash flash target/xtensa-esp32s3-espidf/release/bentoproxy-esp32
```

## Development

### Monitor Serial Output

```bash
espflash monitor
```

### Check Logs

```bash
# Set log level
export RUST_LOG=info

# Or in code
esp_idf_svc::log::EspLogger::initialize_default();
```

### Project Structure

```
esp32/
├── src/
│   └── main.rs         # Main firmware code
├── .cargo/
│   └── config.toml     # Cargo build configuration
├── Cargo.toml          # Dependencies
├── rust-toolchain.toml # Rust toolchain spec
├── build.rs            # Build script
└── README.md           # This file
```

## Protocol

This firmware implements the BentoProxy binary protocol. See [../protocol/README.md](../protocol/README.md) for details.

### Frame Flow

```
ESP32 → Orchestrator: AUTH(device_id, token)
Orchestrator → ESP32: DATA(stream_id=0, ACK flag)  # Auth success

Orchestrator → ESP32: OPEN(stream_id, host, port)
ESP32 → Orchestrator: DATA(stream_id, ACK flag)    # Connection success
ESP32 ↔ Orchestrator: DATA(stream_id, bytes)       # Bidirectional data

Orchestrator → ESP32: CLOSE(stream_id)
ESP32 → Orchestrator: CLOSE(stream_id)
```

## Configuration

### WiFi

Edit `.env` or set environment variables:
- `WIFI_SSID` - Your WiFi network name
- `WIFI_PASSWORD` - Your WiFi password

### Orchestrator

- `ORCHESTRATOR_URL` - WebSocket URL (default: `wss://bentoproxy.com:8443/ws/device`)
- `DEVICE_ID` - Your unique device identifier
- `DEVICE_TOKEN` - Your authentication token

### Limits

- **Max concurrent streams:** 8 (configurable in `main.rs`)
- **TCP buffer size:** 4KB per stream
- **Reconnect delay:** 5 seconds

## Troubleshooting

### Build Errors

**Problem:** `error: linker 'ldproxy' not found`
**Solution:** Run `espup install` and source the environment

**Problem:** `error: failed to run custom build command for esp-idf-sys`
**Solution:** Install build dependencies:
```bash
# Ubuntu/Debian
sudo apt-get install git wget flex bison gperf python3 python3-pip cmake ninja-build ccache libffi-dev libssl-dev dfu-util

# macOS
brew install cmake ninja dfu-util
```

### Flash Errors

**Problem:** `error: failed to open serial port`
**Solution:** Add user to dialout group:
```bash
sudo usermod -a -G dialout $USER
# Log out and back in
```

**Problem:** Device not detected
**Solution:**
- Check USB cable (must support data, not just power)
- Try different USB port
- Press BOOT button while connecting

### Runtime Errors

**Problem:** WiFi connection fails
**Solution:**
- Check SSID and password
- Ensure 2.4GHz WiFi (ESP32 doesn't support 5GHz)
- Check signal strength

**Problem:** WebSocket connection fails
**Solution:**
- Check orchestrator URL
- Verify device ID and token
- Check firewall allows outbound port 8443

**Problem:** Out of memory
**Solution:**
- Reduce `MAX_CONCURRENT_STREAMS` in `main.rs`
- Enable PSRAM if your board supports it

## Performance

- **Power consumption:** ~100mA active, ~10mA idle
- **Throughput:** ~5-10 Mbps per stream
- **Latency:** <50ms additional overhead
- **Memory:** ~100KB static, ~32KB per active stream

## Security

- ✅ TLS 1.2+ for WebSocket connection
- ✅ Device authentication with pre-shared token
- ✅ No payload logging on device
- ✅ Automatic certificate validation

## Contributing

This is open source! Pull requests welcome.

1. Fork the repo
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- **Documentation:** https://docs.bentoproxy.com
- **Discord:** https://discord.gg/bentoproxy
- **Issues:** https://github.com/bentoproxy/bentoproxy-esp32/issues

## Related Projects

- [bentoproxy-protocol](../protocol/) - Binary protocol specification
- [bentoproxy](../orchestrator/) - Orchestrator server (Rust)
- [bentoproxy-desktop](../desktop/) - Desktop node app
