# Suica Viewer

Suica Viewer is a tool for retrieving, displaying, and saving detailed information from FeliCa-based transit IC cards. It uses a remote authentication server to read encrypted areas and offers two entry points: a console-oriented CLI and a Tkinter-based GUI.

## Key Features
- Mutual authentication with a remote server to read encrypted areas
- CLI version: formatted text output for issuance data, balance, history, commuter pass details, and more
- GUI version: visual viewer with tabs for Overview, Issuance Info, Transaction History, Gate History, and Other; includes history filtering and JSON copy/save actions
- Resolves company, line, and station names based on `station_codes.csv`
- Switch authentication servers via the `AUTH_SERVER_URL` environment variable (default: `https://felica-auth.nyaa.ws`)

## Requirements
- Python 3.14 or later
- Poetry 1.8 or later
- FeliCa reader/writer supported by nfcpy (e.g., Sony RC-S380)
- Required drivers and libraries for nfcpy such as `libusb` installed on the PC
- Internet connectivity for communicating with the remote authentication server

## Setup

```bash
poetry install
```

## Usage (CLI)
1. Connect a compatible FeliCa reader to your PC.
2. Set `AUTH_SERVER_URL` if you need to specify a remote server.
3. Present the card while running the command below to output detailed information to the console.

```bash
poetry run suica-viewer
# Example:
# AUTH_SERVER_URL=https://example.com poetry run suica-viewer
```

Main output items
- System issuance information (IDi, PMi)
- Issuance information 1 & 2 (issuer, issuing station, expiration date, etc.)
- Attribute information (card type, balance, transaction counter)
- Transaction history (parses gate entries/exits, purchases, charges, and more)
- Commuter pass data, gate entry/exit records, SF gate entry information

## Usage (GUI)
```bash
poetry run suica-viewer-gui
```

The GUI provides:
- Automatically polls the NFC reader after launch and displays progress while reading when a card is detected
- Overview tab summarizing key fields
- Issuance Info tab showing issuer, station, IDs, and other details
- History tab displaying transaction history in a table with full-text filtering via the input box (`Ctrl+F` / `Cmd+F` to focus)
- Gates tab showing gate history, device numbers, amounts, commuter sections, and SF gate entry data
- Other tab for inspecting unknown fields
- Details tab for viewing the card information JSON and copying it to the clipboard or saving it to a file

## Authentication Server Configuration
- Default: `https://felica-auth.nyaa.ws`
- Set the base URL via the `AUTH_SERVER_URL` environment variable to switch servers (no trailing slash required).
- The server must provide the following endpoints:
  - `POST /mutual-authentication`
  - `POST /encryption-exchange`
- During mutual authentication, commands and responses are relayed to the card. Sensitive data such as personal information or card identifiers may be transmitted, so only connect to trusted environments.

## Station Code Data
- `suica_viewer/station_codes.csv` contains JR East and other station codes, allowing the app to resolve company, line, and station names from the line code and station index.
- Replace the CSV to use a custom dataset if necessary.

## Troubleshooting
- Error message `Unable to initialize NFC reader`: ensure the appropriate drivers are installed and the user has permission to access the USB device.
- Frequent `Server communication error`: check the authentication server URL and your network connection. Adjust `AUTH_SERVER_URL` if needed.
- Message `Detected a non-FeliCa tag`: make sure you are presenting a supported card.

## Notes for Development
- Code formatting: `poetry run black suica_viewer`
- The GUI does not support hot reload; restart the app after UI changes.
- Build artifacts such as `__pycache__` are not included in the repository; clean them up manually when needed.

## Author

- KIRISHIKI Yudai

## License

[MIT](https://opensource.org/licenses/MIT)

Copyright (c) 2025 KIRISHIKI Yudai
