# Suica Viewer

Suica Viewer reads, displays, and saves detailed data from FeliCa-based transit IC cards. Encrypted areas are unlocked through a remote authentication server. It ships as a Tauri desktop app and a CLI.

Reader control and the FeliCa protocol come from [felica](https://github.com/soltia48/felica-rs).

## Key Features
- Reads encrypted areas after mutual authentication with a remote server
- Desktop app: Overview, Card Info, Transaction History, Gates, and Data tabs, with history search, column sorting, and JSON/CSV export
- CLI: formatted output of issuance data, balance, history, commuter pass, and more
- Company, line, and station names resolved from `station_codes.csv`, compiled into the executable
- Authentication server set with `AUTH_SERVER_URL` (default: `https://felica-auth.nyaa.ws`)

## Screenshots

The interface is in Japanese. These screenshots use the bundled demo data; run `suica-viewer --demo` to try it without a reader.

### Overview

Balance, commuter pass, and recent transactions.

![Overview tab in the Japanese interface, showing the demo card balance, commuter pass, and recent transactions](docs/screenshots/overview.png)

### Transaction History

Search, sort by any column, and show detail columns such as payment type and device.

![Transaction History tab with a search field above the demo card's transaction table](docs/screenshots/history.png)

<details>
<summary>Card Info, Gates, Data, and dark theme</summary>

### Card Info

Issuance details, card attributes, and commuter pass records.

![Card Info tab displaying issuance details, card attributes, and commuter pass information from the demo data](docs/screenshots/card-info.png)

### Gates

Gate entry/exit records, SF gate entry, and paid-ticket records when present.

![Gates tab displaying the demo card's gate entry and exit history and related gate records](docs/screenshots/gates.png)

### Data

Copy or save the card data as JSON, or export the history as CSV.

![Data tab with JSON and CSV export buttons above a preview of the demo card's JSON data](docs/screenshots/data.png)

### Dark Theme

![Overview tab in dark theme, showing the demo card balance, commuter pass, and recent transactions](docs/screenshots/overview-dark.png)

</details>

## Requirements
- [Rust](https://www.rust-lang.org/) 1.88 or later (edition 2024), to build from source
- [Node.js](https://nodejs.org/) 20.19+ or 22.12+ and npm, to build the front end
- A FeliCa reader supported by felica:

| Device | VID:PID |
| --- | --- |
| Sony RC-S380 (Port-100) | 054C:06C1, 054C:06C3 |
| Sony RC-S300 (Port-400) | 054C:0DC8, 054C:0DC9, 054C:0D8F |
| Sony RC-S320 | 054C:01BB |
| Sony RC-S330 / RC-S360 / RC-S370 (RC-S956) | 054C:02E1, 054C:0193 |

- A libusb-compatible driver for the reader (see [Reader Driver Setup](#reader-driver-setup))
- Internet access to reach the authentication server

## Installation

### Prebuilt executables
Each release ships the `suica-viewer` desktop app and the `suica-viewer-cli` console program, with the station data and UI embedded. Download the files for your platform from [Releases](../../releases), along with `SHA256SUMS.txt` to verify them.

| Platform | Asset suffix |
| --- | --- |
| Linux (x86_64) | `-linux-x86_64` |
| Windows (x86_64) | `-windows-x86_64.exe` |
| macOS (Apple Silicon) | `-macos-arm64` |
| macOS (Intel) | `-macos-x86_64` |

macOS builds are unsigned, so Gatekeeper blocks the first launch. Allow it under System Settings → Privacy & Security.

The reader driver still needs setting up; see [Reader Driver Setup](#reader-driver-setup).

### From source

```bash
npm ci --prefix ui
npm exec --prefix ui -- tauri build --no-bundle
cargo build --release --locked --bin suica-viewer-cli
# Artifacts: target/release/suica-viewer, target/release/suica-viewer-cli
```

`rusb` builds libusb from source, so no separate install is needed. On Linux, install the [Tauri system dependencies](https://v2.tauri.app/start/prerequisites/#linux) and `libudev-dev`.

## Reader Driver Setup
felica accesses the reader through libusb, which needs a driver it can claim the device with.

**Windows.** Windows binds its own driver, which libusb cannot open. Replace it with **WinUSB** using [Zadig](https://zadig.akeo.ie/). Vendor software such as Sony's NFC Port Software then stops working until you restore the original driver in Device Manager.

**Linux.** Give your user access to the device:

```bash
# Example udev rule for the Sony RC-S380 (0x054c:0x06c1, 0x054c:0x06c3)
echo 'SUBSYSTEM=="usb", ATTRS{idVendor}=="054c", ATTRS{idProduct}=="06c3", GROUP="plugdev", MODE="0664"' \
  | sudo tee /etc/udev/rules.d/60-suica-viewer.rules
sudo udevadm control --reload-rules
```

Without the rule, run as root.

**macOS.** No setup needed.

## Usage (CLI)
Connect the reader, optionally set `AUTH_SERVER_URL`, run the command, and tap a card.

```bash
suica-viewer-cli
# Example:
# AUTH_SERVER_URL=https://example.com suica-viewer-cli
```

Output starts with a balance summary, followed by colored tables. Color turns off when stdout is not a TTY or `NO_COLOR` is set.

| Option | Description |
| --- | --- |
| `--json` | Output JSON instead of tables |
| `-v`, `--verbose` | Include device numbers, raw codes, and other detail fields |
| `--no-color` | Disable ANSI color |
| `--server URL` | Authentication server URL (overrides `AUTH_SERVER_URL`) |

Output sections:
- System issuance data (IDi, PMi)
- Issuance info (issuer, issuing station, expiry, collected flag, and more)
- Attributes (card type, balance, transaction counter)
- Transaction history (gate entry/exit, purchases, top-ups), with the balance change per entry
- Commuter pass, gate entry/exit records, SF gate entry
- Paid-ticket / express-gate records (service `0x184B`), read only when the card has them; skipped without side effects if the card or server lacks them

## Usage (Desktop App)

```bash
suica-viewer
```

- Shows a prompt to tap a card, the read progress, or a reader error with how to fix it. Tabs appear once a card is read.
- Updates live as cards are detected. Removing the card returns to the prompt.
- Themes: system, light, and dark.
- The Tauri process owns the reader and sends card data to the UI over local IPC. No HTTP server is started and nothing is exposed to the network.

| Option | Description |
| --- | --- |
| `--server URL` | Authentication server URL (overrides `AUTH_SERVER_URL`) |
| `--demo` | Preview the UI with a built-in sample card, without a reader |

## Authentication Server
- Default: `https://felica-auth.nyaa.ws`
- Set `AUTH_SERVER_URL` to a base URL to switch servers (no trailing slash).
- The server must provide `POST /mutual-authentication`.

### What is sent where
The server takes part in **mutual authentication only**. It builds command frames that are relayed to the card, and receives the card's replies, so it sees the IDm, PMm, and authentication responses.

After authentication, the server returns the session material (DES session key, transaction ID, transaction counter) and discards the session. All encrypted reads then run **directly between this process and the card**: **balance, history, name, and other card contents never reach the server**, and the long-term keys never leave it.

Card identifiers are still sent, so use only servers you trust.

### Which nodes are authenticated
The viewer only reads, so it authenticates each service's **read-only code** rather than its read/write code. The resulting session key cannot modify the card, and servers running with `--read-only-nodes` accept the request as-is.

| Service | Data | Key |
| --- | --- | --- |
| `0x004A` | Issuance info | required |
| `0x0816` | Misc (purpose unconfirmed) | required |
| `0x08CA` | Last top-up | required |
| `0x104A` | Commuter pass | required |
| `0x008B` | Attributes / balance | not required |
| `0x090F` | Transaction history | not required |
| `0x108F` | Gate entry/exit | not required |
| `0x10CB` | SF gate entry | not required |
| `0x184B` | Paid ticket (when present) | not required |

FeliCa requires key-requiring nodes to come before key-free ones, hence this order. The server needs keys for these read-only codes, not just the read/write ones.

## Station Code Data
`assets/station_codes.csv` maps line and station order codes to company, line, and station names for JR East and other operators. It is compiled in at build time; edit it and rebuild to change the data.

## Troubleshooting
- `Operation not supported or unimplemented on this platform` (Windows): no libusb-compatible driver is bound. Install WinUSB with Zadig (see [Reader Driver Setup](#reader-driver-setup)). Running as administrator does not help.
- `Access denied (insufficient permissions)` (Linux): add the udev rule above or run as root.
- `NFC リーダーを初期化できません` / `reader not found`: the reader is not connected, or its VID/PID is not supported.
- Repeated `サーバ通信エラー`: check `AUTH_SERVER_URL` and your network connection.

Set `RUST_LOG=debug` for verbose logs, including frames exchanged with the card.

## Development Notes
- Install UI dependencies: `npm ci --prefix ui`
- Run the app in demo mode: `npm exec --prefix ui -- tauri dev -- -- --demo`
- Check the front end: `npm --prefix ui run build`
- Check Rust: `cargo fmt --all`, `cargo clippy --workspace --all-targets`, `cargo test --workspace`
- Pushing a `v*` tag runs [`.github/workflows/release.yml`](.github/workflows/release.yml), which builds every platform and attaches the binaries to a GitHub Release.

## Author

- KIRISHIKI Yudai

## License

[MIT](https://opensource.org/licenses/MIT)

Copyright (c) 2025 KIRISHIKI Yudai
