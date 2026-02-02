# Classic Protocol Diagnostics

This script is a standalone diagnostic tool for testing Classic Casambi protocol communication. It can be run outside Home Assistant to debug why Classic control commands might not be working.

## Prerequisites

1. Python 3.10+
2. `bleak` package installed: `pip install bleak`
3. Optional: `httpx` for cloud key fetching: `pip install httpx`
4. A Classic Casambi network (protocol version < 10)

## Usage

```bash
cd casambi-bt
python scripts/classic_diagnostics.py <network_uuid> <password>

# With options:
python scripts/classic_diagnostics.py CE42027B8FDE mypassword --output diag.log --debug
```

## Options

- `uuid`: Network UUID (12 hex chars, e.g., "CE42027B8FDE")
- `password`: Network password
- `--output`, `-o`: Output log file (default: classic_diag_<timestamp>.log)
- `--timeout`, `-t`: BLE scan timeout in seconds (default: 10)
- `--debug`, `-d`: Enable debug logging

## Environment Variables

- `CASAMBI_BT_CLASSIC_FORMAT=simple`: Use alternative simple packet format from BLE captures instead of the Android u1.C1753e format

## What It Does

1. **Cloud Key Fetch**: Attempts to fetch visitor/manager keys from Casambi cloud API
2. **BLE Discovery**: Scans for the network device
3. **GATT Enumeration**: Lists all services and characteristics
4. **Classic Detection**: Probes for Classic protocol support (CA51/CA52 or auth char)
5. **Notification Subscribe**: Subscribes to receive state updates
6. **Command Tests**: Sends level control commands (0 → 255 → 0)
7. **Format Comparison**: Optionally tests both packet formats

## Output Files

- `classic_diag_<timestamp>.log`: Full diagnostic log
- `classic_diag_<timestamp>_report.json`: Structured JSON report

## Interpreting Results

### Good Signs
- `[CLASSIC_DIAG_CONNECT] Conformant/Legacy Classic detected`
- `[CLASSIC_DIAG_KEYS] visitor=True` or `manager=True`
- `[CLASSIC_DIAG_TX_RESULT] result=ok`
- `[CLASSIC_DIAG_RX] #N ...` (receiving notifications)

### Warning Signs
- `[CLASSIC_DIAG_KEYS] visitor=False manager=False` - Missing keys
- `TX packets sent: N, RX packets received: 0` - Not receiving updates
- `[CLASSIC_DIAG_TX_RESULT] result=error: ...` - Write failures

## Sharing Logs

When sharing logs for analysis:
1. The log files do not contain passwords or raw keys
2. Connection hash and packet data is included (needed for debugging)
3. Share both the `.log` and `_report.json` files
