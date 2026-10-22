![PyPI](https://img.shields.io/pypi/v/casambi-bt-revamped)
[![Discord](https://img.shields.io/discord/1186445089317326888)](https://discord.gg/jgZVugfx)

# Casambi Bluetooth Revamped - Python library for Casambi networks

This is a customized fork of the original [casambi-bt](https://github.com/lkempf/casambi-bt) library with additional features and should only be used for special needs:

- **Switch event support** - Receive button press/release/hold events from Casambi switches (wired + wireless)
- **Improved relay status handling** - Better support for relay units
- **Classic protocol (experimental)** - Basic unit control for Classic (legacy) firmware networks
- **Bug fixes and improvements** - Various fixes based on real-world usage

This library provides a bluetooth interface to Casambi-based lights. It is not associated with Casambi.

For Home Assistant integration using this library, see [casambi-bt-hass](https://github.com/rankjie/casambi-bt-hass).

## Getting started

This library is available on PyPi:

```
pip install casambi-bt-revamped
```

Have a look at `demo.py` for a small example.

### Switch Event Support

This library supports receiving physical switch events as a decoded stream of INVOCATION frames (ground truth from the official Android app).

Semantic event types supported by the capture-derived switch decoder:
- `button_press`
- `button_release` (short press; `press_duration_ms` is set when reported by the switch itself)
- `button_hold` (long press threshold reached)
- `button_release_after_hold`
- `input_event` (NotifyInput frame with an unknown code; diagnostics only)

Every event also carries `source` (`button_event` = the switch's own ButtonEvent stream,
`notify_input` = NotifyInput stream) and `held` (True for hold / release-after-hold).

```python
from CasambiBt import Casambi

def handle_switch_event(event_data):
    print(
        "Switch event:",
        {
            "unit_id": event_data.get("unit_id"),
            "button": event_data.get("button"),
            "event": event_data.get("event"),
            # INVOCATION metadata (useful for debugging/correlation)
            "event_id": event_data.get("event_id"),
            "opcode": event_data.get("opcode"),
            "target_type": event_data.get("target_type"),
            "origin": event_data.get("origin"),
            "age": event_data.get("age"),
            # NotifyInput fields (target_type=0x12)
            "input_code": event_data.get("input_code"),
            "input_channel": event_data.get("input_channel"),
            "input_value16": event_data.get("input_value16"),
            "input_mapped_event": event_data.get("input_mapped_event"),
        },
    )

casa = Casambi()
# ... connect to network ...

# Register switch event handler
casa.registerSwitchEventHandler(handle_switch_event)

# Events will be received when buttons are pressed/released
```

Notes:
- Wireless (battery) switches send a "button stream" (target_type `0x06`) for press/release with the press duration; a mains unit additionally reports the same action as NotifyInput (target_type `0x12`), which is also the only carrier of hold.
- Wired switches often only send NotifyInput (target_type `0x12`); its `input_code` is mapped into `button_press/button_release/...`.
- Mesh copies are suppressed by invocation identity for at least 3 seconds, extended to the declared lifetime when longer. The legacy switch API also pairs ButtonEvent and NotifyInput reports by count within 3 seconds. That heuristic can consume a real event when rapid clicks have complementary losses across the two sources. Its 500 ms long-press threshold and four-gang button labels are capture-derived assumptions.

### Selecting a GATT node

Pass a node's `BLEDevice` to `connect` and set `networkAddress` to the original
network MAC address. Cloud access and cached keys continue to use that network
identity while the Bluetooth connection uses the selected node. Omitting
`networkAddress` preserves the existing connection behavior.

### Network Events

`registerNetworkEventHandler` exposes profile-driven state changes and type 7 protocol observations for the whole connected network. The type 7 path preserves ButtonEvent and NotifyInput separately, including their raw indices, flags, origin/target, optional origin handle, packet sequence and input fields. It does not apply the legacy switch API's cross-source pairing or inferred long-press threshold.

The local Mac viewer uses WebSocket updates, preserves expanded details, supports optional LAN listeners and saves event history across restarts. See [Network Events](docs/network-events.md) for the API, protocol evidence and demo commands.

For the parsing details and field layout, see `doc/PROTOCOL_PARSING.md`.

### Classic (Legacy Firmware) Support (Experimental)

This library can also connect to **Classic** Casambi networks and send **unit control** commands.

How it works (ground truth: the bundled Android app sources):
- Classic devices expose a CMAC-signed data channel (`ca51`/`ca52`) or a "Classic conformant" signed channel on the EVO UUID.
- The cloud network JSON exposes `visitorKey` / `managerKey` (hex strings) instead of an EVO `keyStore`.
- Commands are signed with AES-CMAC and sent as Classic "command records" (see `doc/PROTOCOL_PARSING.md`).

Environment flags:
- `CASAMBI_BT_DISABLE_CLASSIC=1` to refuse Classic connections (fail fast)
- `CASAMBI_BT_CLASSIC_USE_MANAGER=1` to sign with the 16-byte manager signature (default is visitor/4-byte prefix)
- `CASAMBI_BT_LOG_RAW_NOTIFIES=1` to enable very verbose per-notify hexdumps (mainly for Classic debugging)

### MacOS

MacOS [does not expose the Bluetooth MAC address via their official API](https://github.com/hbldh/bleak/issues/140),
if you're running this library on MacOS, it will use an undocumented IOBluetooth API to get the MAC Address.
Without the real MAC address the integration with Casambi will not work.
If you're running into problems fetching the MAC address on MacOS, try it on a Raspberry Pi.

### Casambi network setup

If you have problems connecting to the network please check that your network is configured appropriately before creating an issue. The network I test this with uses the **Evoultion firmware** and is configured as follows (screenshots are for the iOS app but the Android app should look very similar):

![Gateway settings](/doc/img/gateway.png)
![Network settings](/doc/img/network.png)
![Performance settings](/doc/img/perf.png)

## Development / Offline Testing

This repo includes log-driven unit tests for switch parsing:

```bash
cd casambi-bt
python -m unittest -v
```
