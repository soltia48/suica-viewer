# Suica Viewer

Suica Viewer is a tool for retrieving, displaying, and saving detailed information from FeliCa-based transit IC cards. It uses a remote authentication server to read encrypted areas and offers two entry points: a console-oriented CLI and a local web GUI.

Reader control and the FeliCa protocol are provided by [felica-rs](https://github.com/soltia48/felica-rs).

## Key Features
- Mutual authentication with a remote server to read encrypted areas
- CLI version: formatted text output for issuance data, balance, history, commuter pass details, and more
- Web GUI version: visual viewer with tabs for Overview, Card Info, Transaction History, Gates, and Data; includes history filtering and JSON copy/save actions
- Resolves company, line, and station names from `station_codes.csv`, which is compiled into the executable
- Switch authentication servers via the `AUTH_SERVER_URL` environment variable (default: `https://felica-auth.nyaa.ws`)

## Requirements
- [Rust](https://www.rust-lang.org/) 1.85 or later, to build from source (the crate uses edition 2024)
- A FeliCa reader/writer supported by felica-rs

| Device | VID:PID |
| --- | --- |
| Sony RC-S380 (Port-100) | 054C:06C1, 054C:06C3 |
| Sony RC-S300 (Port-400) | 054C:0DC8, 054C:0DC9, 054C:0D8F |
| Sony RC-S320 | 054C:01BB |
| Sony RC-S330 / RC-S360 / RC-S370 (RC-S956) | 054C:02E1, 054C:0193 |

- A libusb-compatible driver bound to the reader — see [Reader Driver Setup](#reader-driver-setup)
- Internet connectivity for communicating with the remote authentication server

## Installation

### Prebuilt executables
Every release ships standalone executables for `suica-viewer` and `suica-viewer-web`. The station dataset and the web UI are embedded in the binaries, so there are no extra files to install. Download the file matching your platform from the [Releases](../../releases) page, alongside `SHA256SUMS.txt` to verify it.

| Platform | Asset suffix |
| --- | --- |
| Linux (x86_64) | `-linux-x86_64` |
| Windows (x86_64) | `-windows-x86_64.exe` |
| macOS (Apple Silicon) | `-macos-arm64` |
| macOS (Intel) | `-macos-x86_64` |

The macOS builds are unsigned, so Gatekeeper blocks the first launch. Allow the executable under System Settings → Privacy & Security.

You still need to set up the reader driver. See [Reader Driver Setup](#reader-driver-setup).

### From source

```bash
cargo build --release
# Artifacts: target/release/suica-viewer, target/release/suica-viewer-web
```

`rusb` builds libusb from source, so there is no separate libusb install. On Linux it links against libudev for device enumeration, so install `libudev-dev` (Debian/Ubuntu) first.

## Reader Driver Setup
felica-rs talks to the reader through libusb, which needs a driver it can claim the USB device with.

**Windows.** By default Windows binds its own driver to the reader and libusb cannot open it. Use [Zadig](https://zadig.akeo.ie/) to replace the reader's driver with **WinUSB**. Once replaced, vendor software (such as Sony's NFC Port Software) cannot use the reader until you restore the original driver from Device Manager.

**Linux.** Grant your user access to the device.

```bash
# Example udev rule for the Sony RC-S380 (0x054c:0x06c1, 0x054c:0x06c3)
echo 'SUBSYSTEM=="usb", ATTRS{idVendor}=="054c", ATTRS{idProduct}=="06c3", GROUP="plugdev", MODE="0664"' \
  | sudo tee /etc/udev/rules.d/60-suica-viewer.rules
sudo udevadm control --reload-rules
```

Without the rule you have to run as root.

**macOS.** No extra setup is required.

## Usage (CLI)
1. Connect a supported FeliCa reader.
2. Optionally set `AUTH_SERVER_URL` to point at your authentication server.
3. Run the command below and tap a card; the details are printed to the console.

```bash
suica-viewer
# Example:
# AUTH_SERVER_URL=https://example.com suica-viewer
```

Output leads with a balance summary and is formatted as colored tables. Color is disabled automatically when stdout is not a TTY or `NO_COLOR` is set.

Options
- `--json` — emit JSON instead of tables, for scripting
- `-v`, `--verbose` — also show device numbers, raw codes, and other detail fields
- `--no-color` — disable ANSI color
- `--server URL` — authentication server URL (takes precedence over `AUTH_SERVER_URL`)

Main output sections
- System issuance data (IDi, PMi)
- Issuance info (issuer, issuing station, expiry, collected/invalidated flag, and so on)
- Attribute info (card type, balance, transaction counter)
- Transaction history, decoded per entry (gate entry/exit, purchases, top-ups) with the per-transaction balance change
- Commuter pass info, gate entry/exit records, SF gate entry records
- Paid-ticket / express-gate records (service `0x184B`) — probed and read only when the card carries it. Cards without it, or servers without the matching key, are skipped without affecting anything else.

## Usage (Web GUI)
A browser can neither reach a USB reader nor relay the mutual authentication, so `suica-viewer-web` runs a local server that owns the reader and streams card data to the page over Server-Sent Events.

```bash
suica-viewer-web
# Opens http://127.0.0.1:8765/ in your browser by default
```

- Cards are detected automatically and the page updates live, with no reload. Includes the balance hero card, tabbed layout, sortable transaction history with per-transaction deltas, gate tables, JSON/CSV export, and light/dark themes.
- Removing the card from the reader clears the page and waits for the next one.
- Binds to `127.0.0.1` only by default. `--host 0.0.0.0` exposes it to the LAN — note that card data then travels over the network.

Options

| Flag | Description |
| --- | --- |
| `--host` / `--port` | Bind address (default `127.0.0.1:8765`) |
| `--server URL` | Authentication server URL (takes precedence over `AUTH_SERVER_URL`) |
| `--no-browser` | Do not open a browser on startup |
| `--demo` | Preview the UI with a built-in sample card, without a reader |

## Authentication Server
- Default: `https://felica-auth.nyaa.ws`
- Set the `AUTH_SERVER_URL` environment variable to a base URL to switch servers (no trailing slash needed).
- The server must expose `POST /mutual-authentication`.

### What is sent where
The server takes part in the **mutual authentication only**. During it, command frames the server builds are relayed to the card and the card's replies are sent back, so the IDm, PMm, and the card's authentication responses do reach the server.

Once authentication succeeds the server returns the ephemeral session material (DES session key, transaction ID, transaction counter) and discards the session. Every encrypted Read after that runs **directly between this process and the card**, so **balance, history, name, and the rest of the card's contents never reach the server**. The long-term keys, correspondingly, never leave it.

Card identifiers are still transmitted, so only connect to servers you trust.

### Which nodes are authenticated
The viewer only reads, so it authenticates the **read-only code** of each service rather than the read/write code that exposes the same data. The session key it receives therefore cannot modify the card, and an auth server running with `--read-only-nodes` authenticates the request as-is.

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

FeliCa requires every key-requiring node to be listed before any key-free one, which is why the list is ordered this way. The server must hold keys for these read-only codes, not only for their read/write counterparts.

## Station Code Data
- `assets/station_codes.csv` holds station codes for JR East and other operators, resolving company, line, and station names from a line code and station order code.
- The file is compiled into the executable at build time. To use a different dataset, edit the CSV and rebuild.

## Troubleshooting
- `Operation not supported or unimplemented on this platform` on Windows: libusb sees the reader but cannot open it because no libusb-compatible driver is bound. Install the WinUSB driver with Zadig as described in [Reader Driver Setup](#reader-driver-setup). Running as administrator does not help.
- `Access denied (insufficient permissions)` on Linux: you lack access to the USB device. Add the udev rule above or run as root.
- `NFC リーダーを初期化できません` / `reader not found`: the reader is not connected, or its VID/PID is not in the supported list.
- Persistent `サーバ通信エラー`: check the authentication server URL and your network connection, adjusting `AUTH_SERVER_URL` as needed.

Set `RUST_LOG=debug` for verbose logging, including the frames exchanged with the card.

## Development Notes
- Format, lint, and test: `cargo fmt --all` / `cargo clippy --all-targets` / `cargo test`
- To check the web UI without a reader: `cargo run --bin suica-viewer-web -- --demo`
- Pushing a `v*` tag runs [`.github/workflows/release.yml`](.github/workflows/release.yml), which builds every platform and attaches the executables to a GitHub Release.

## Author

- KIRISHIKI Yudai

## License

[MIT](https://opensource.org/licenses/MIT)

Copyright (c) 2025 KIRISHIKI Yudai
