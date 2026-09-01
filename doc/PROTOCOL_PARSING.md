# Casambi Protocol Parsing (casambi-bt-revamped)

This document describes the on-air parsing implemented in `casambi-bt-revamped`, based on the official Android app source bundled in this repo.

Ground truth (Android):
- INVOCATION stream parsing: `casambi-android/sources/V1/C1775b.java` method `Q(Q2.h)`
- Unit state parsing: `casambi-android/sources/V1/C1775b.java` method `V(Q2.h)`
- Function opcode ordinals: `casambi-android/sources/V1/EnumC1777d.java`
- Classic GATT UUIDs: `casambi-android/sources/t1/C1713d.java` (UUIDs `ca5a/ca51/ca52`)
- Classic signed header + CMAC: `casambi-android/sources/t1/P.java` method `o(...)`
- Classic command record encoding: `casambi-android/sources/u1/C1753e.java` method `a(P)`
- Classic command ordinals: `casambi-android/sources/u1/EnumC1754f.java`

## Protocol Variants: EVO vs Classic

Casambi has two protocol families on BLE:

- **EVO (Evolution firmware)**: encrypted channel + decrypted packet types (`0x06`, `0x07`, `0x09`).
- **Classic (legacy firmware)**: a **CMAC-signed** data channel; commands are sent as "command records".

This library:
- Supports **EVO** parsing and switch events (packet types `0x06/0x07/0x09`).
- Supports **Classic** for **unit control** (experimental; relies on keys from cloud JSON `visitorKey`/`managerKey` and on-device GATT signing).

Protocol selection is automatic at runtime based on the connected device's GATT:
- If the device exposes `ca51` + `ca52`, it is treated as Classic.
- Otherwise, if `CASA_AUTH_CHAR_UUID` (`c9ffde48-...`) is readable:
  - If the first byte is `0x01` (NodeInfo), it is EVO.
  - Otherwise it is treated as "Classic conformant" (Classic signed channel on the EVO UUID).

Implementation:
- `casambi-bt/src/CasambiBt/_client.py` `CasambiClient.connect()` chooses `ProtocolMode`.

## Decrypted Packet Types

After link-layer decryption+signature verification, the first byte is a packet type:
- `0x06` = UnitState stream
- `0x07` = INVOCATION stream (this is where switch/input/trace events live)
- `0x09` = NetworkConfig (ignored by this library for now)

Implementation entrypoints:
- `casambi-bt/src/CasambiBt/_client.py` `_establishedNofityCallback()`
- `casambi-bt/src/CasambiBt/_client.py` `_parseUnitStates()` (type `0x06`)
- `casambi-bt/src/CasambiBt/_switch_events.py` `SwitchEventStreamDecoder.decode()` (type `0x07`)

## Packet Type 0x07: INVOCATION Stream

Decrypted type `0x07` is a stream of INVOCATION frames (it is *not* a custom "0x08/0x10 switch message" transport).

Android parsing (`C1775b.Q`) reads:
- `flags` (uint16)
- `opcode` (uint8) -> `EnumC1777d.h(byte)`
- `origin` (uint16)
- `target` (uint16)
- `age` (uint16)
- optional `origin_handle` (uint8) if `flags & 0x0200` is set
- `payload` length is `flags & 0x3F` bytes

Python implementation:
- `casambi-bt/src/CasambiBt/_invocation.py` `parse_invocation_stream()`

Useful derived fields:
- `target_type = target & 0xFF`
- `unit_id = (target >> 8) & 0xFF`

### Switch "Button Stream" (target_type 0x06)

Android prints a "Switch event" log when:
- `target_type == 6`
- `payload_len >= 3`
- `opcode.ordinal()` is in `[29..36]` (FunctionButtonEvent0..7)

The first payload byte encodes:
- `pressed = (payload[0] & 0x80) != 0`
- `P = (payload[0] >> 3) & 0x0F`
- `S = payload[0] & 0x07`

Observed payload layout (captures of LEDsGO 4CHANNEL_SW EVO):
- `P` equals the button index.
- `payload[1..2]` (big-endian) is the press duration in 10 ms ticks: `0x0002` on press frames,
  130-220 ms on short-press releases, 1.9-3.5 s on long-press releases.

Python mapping:
- `casambi-bt/src/CasambiBt/_switch_events.py` treats these as semantic events:
  - `pressed -> "button_press"`
  - `!pressed -> "button_release"`, or `"button_release_after_hold"` when the duration is >= 500 ms
  - `press_duration_ms` and `held` are exposed on the event
- 4-gang label mapping observed in Android captures (matches `switchConfig.switches[].index + 1`):
  - ButtonEvent0 -> label 4
  - ButtonEvent1 -> label 1
  - ButtonEvent2 -> label 2
  - ButtonEvent3 -> label 3

Duplicate handling (all frame kinds):
- `origin` is `unit << 8 | handle`; `handle` is the emitting unit's invocation counter and
  advances with every invocation it sends, so two physical presses never share it.
- `age` is in 10 ms ticks and `lifetime` (flags bits 11-14) in seconds. The mesh re-floods a
  frame until its lifetime expires; every copy has the same origin/opcode/target/payload and a
  larger `age`. Button frames were seen with lifetime 1 s, NotifyInput with 2 s.
- The decoder drops a frame whose `(origin, opcode, target, payload)` was already processed in
  the last 3 s. No "currently pressed" state is kept, so a lost frame cannot suppress a later one.

### NotifyInput Stream (target_type 0x12)

Android prints an "Input event" log when:
- `target_type == 18 (0x12)`
- `payload_len >= 2`
- `opcode.ordinal()` is in `[64..71]` (FunctionNotifyInput0..7)

Android extracts:
- `input_index = opcode.ordinal() - 64`
- `input_channel = payload[1] & 7`
- `value16 = little-endian payload[2..3]` when `payload_len >= 4`, else `0`
- `e = payload[0] & 0xFF` (we expose this as `input_code`)

Python exposure:
- NotifyInput events carry `input_index`, `input_code`, `input_b1`, `input_channel`, `input_value16`
  and `source="notify_input"`.

Observed semantic mapping (from captures; Android itself only logs the bytes):
- `input_code 0x01` -> `button_press`
- `input_code 0x02` -> `button_release`
- `input_code 0x09` -> `button_hold`
- `input_code 0x0C` -> `button_release_after_hold`
- anything else -> `input_event`

Wired vs wireless behavior:
- Wired switches (e.g. Scemtec SC-TI-CAS) only send NotifyInput frames, from themselves; all
  four codes are emitted as semantic events.
- Wireless switches (e.g. LEDsGO 4CHANNEL_SW EVO) send the button stream themselves, and a
  mains unit reports the same action as NotifyInput `0x02/0x09/0x0C` (never `0x01`), in either
  order and up to ~1 s apart.

Cross-source pairing:
- For each `(unit_id, button, press|release)` the first report from either stream is emitted;
  the report from the other stream inside 3 s is consumed (counted, not stateful). If one stream
  loses a frame, the other one still produces the event.

## Packet Type 0x06: UnitState Stream

Decrypted type `0x06` is a stream of unit state records.

Android parsing (`C1775b.V`) layout per record:
- `unit_id` (uint8)
- `flags` (uint8)
- `b8` (uint8): upper nibble encodes `state_len`, lower nibble encodes `prio`
  - `state_len = ((b8 >> 4) & 0x0F) + 1`
  - `prio = b8 & 0x0F`
- optional bytes:
  - if `flags & 0x04`: `con` (uint8)
  - if `flags & 0x08`: `sid` (uint8)
  - if `flags & 0x10`: `extra_byte` (uint8), else Android uses `0xFF`
- `state` bytes: `state_len` bytes
- padding bytes: `(flags >> 6) & 0x03`

Flags bits used by Python:
- `online = (flags & 0x02) != 0`
- `on = (flags & 0x01) != 0`

Python implementation and exposure:
- `casambi-bt/src/CasambiBt/_client.py` `_parseUnitStates()` emits `IncommingPacketType.UnitState` callbacks with:
  - `id`, `online`, `on`, `state`
  - plus diagnostic fields: `flags`, `prio`, `state_len`, `padding_len`, `con`, `sid`, `extra_byte`, `extra_float`

Unit state decoding:
- `casambi-bt/src/CasambiBt/_unit.py` `Unit.setStateFromBytes()` decodes known controls based on unit type metadata from the cloud.
- Unknown controls are preserved in `UnitState.unknown_controls` and `UnitState.raw_state` for later reverse engineering.

## Debugging Aids

Stable log markers used for offline analysis:
- `[CASAMBI_RAW_PACKET]` encrypted bytes with device sequence
- `[CASAMBI_DECRYPTED]` decrypted bytes (includes packet type byte)
- `[CASAMBI_SWITCH_PACKET]` type `0x07` payload bytes (INVOCATION stream)
- `[CASAMBI_SWITCH_SUMMARY]` frame counts + copy/pair suppression stats
- `[CASAMBI_UNITSTATE_PARSED]` decoded unit state record fields

Log-driven tests:
- `casambi-bt/tests/test_switch_event_logs.py`
- `casambi-bt/tests/test_unit_state_logs.py`

## Classic: Signed Channel + Command Records (Experimental)

### Classic GATT UUIDs

Classic devices use different UUIDs than EVO (ground truth: `t1.C1713d`):
- Service UUID: `0000ca5a-0000-1000-8000-00805f9b34fb`
- Connection hash characteristic: `0000ca51-0000-1000-8000-00805f9b34fb`
- Signed data characteristic (write + notify): `0000ca52-0000-1000-8000-00805f9b34fb`

Some devices expose the Classic signed data channel on the EVO auth characteristic UUID
(`c9ffde48-ca5a-0001-ab83-8f519b482f77`). The library supports both variants.

### Classic Signed Frame Layout

Classic frames are signed with AES-CMAC; the CMAC (or a prefix) is embedded into the header.

Header layout (ground truth: `t1.P.n(...)` + `t1.P.o(...)`):
- `auth_level` (1 byte):
  - `0x02` = visitor (4-byte signature prefix)
  - `0x03` = manager (16-byte signature prefix)
- `sig_prefix` (`sig_len` bytes): placeholder filled with CMAC prefix
- `seq` (2 bytes, big-endian): included in CMAC input
- `payload` (remaining bytes): command record stream

CMAC input (ground truth: `t1.P.o(...)`):
- `connection_hash[0:8] + (seq || payload)`

### Classic Command Record Encoding

Classic control commands are encoded as records (ground truth: `u1.C1753e.a(P)`):

Record layout:
- `b0`: encoded length byte: `(record_len + 239) & 0xFF`
- `b1`: `ordinal | flags`
  - `flags & 0x40`: `div` byte present
  - `flags & 0x80`: `target_id` byte present
  - `ordinal = b1 & 0x3F`
- `div` (1 byte, usually present; Android increments 1..255)
- `target_id` (1 byte, optional; Android only writes when `> 0`)
- `lifetime` (1 byte, Android uses `200`)
- `payload` (0..N bytes; command-specific)

The library builds records via:
- `casambi-bt/src/CasambiBt/_client.py` `CasambiClient.buildClassicCommand(...)`

### Classic Control Coverage

The high-level `Casambi` APIs map to Classic command ordinals (ground truth: `u1.EnumC1754f` + `u1.C1751c`):
- Level/brightness: All=4, Unit=7, Group=26
- Temperature: All=5, Unit=8, Group=27
- RGB Color: All=6, Unit=9, Group=28
- Vertical: All=22, Unit=24, Group=29
- White: All=23, Unit=25, Group=30

Implementation:
- `casambi-bt/src/CasambiBt/_casambi.py` methods `setLevel`, `setTemperature`, `setColor`, etc.

### Classic Debug Logging

Markers:
- `[CASAMBI_CLASSIC_CONN_HASH]` first 8 bytes used for signing (debug)
- `[CASAMBI_CLASSIC_TX]` signed TX metadata (debug)
- `[CASAMBI_CLASSIC_TX_RAW]` signed TX bytes (debug)
- `[CASAMBI_CLASSIC_RX_RAW]` RX bytes (debug)
- `[CASAMBI_CLASSIC_RX_VERIFY]` CMAC verification result (debug)
- `[CASAMBI_CLASSIC_CMD]` best-effort parsed command records (debug)

To avoid log spam, raw notify hexdumps are opt-in:
- Set `CASAMBI_BT_LOG_RAW_NOTIFIES=1` to log per-notify hexdumps in `_client.py`.
