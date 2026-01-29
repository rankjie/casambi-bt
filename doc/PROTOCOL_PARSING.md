# Casambi Protocol Parsing (casambi-bt-revamped)

This document describes the on-air parsing implemented in `casambi-bt-revamped`, based on the official Android app source bundled in this repo.

Ground truth (Android):
- INVOCATION stream parsing: `casambi-android/sources/V1/C1775b.java` method `Q(Q2.h)`
- Unit state parsing: `casambi-android/sources/V1/C1775b.java` method `V(Q2.h)`
- Function opcode ordinals: `casambi-android/sources/V1/EnumC1777d.java`

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

Python mapping:
- `casambi-bt/src/CasambiBt/_switch_events.py` treats these as semantic events:
  - `pressed -> "button_press"`
  - `!pressed -> "button_release"`
- 4-gang label mapping observed in Android captures:
  - ButtonEvent0 -> label 4
  - ButtonEvent1 -> label 1
  - ButtonEvent2 -> label 2
  - ButtonEvent3 -> label 3

Duplicate handling:
- Wireless switches retransmit the same pressed state multiple times.
- The decoder suppresses repeated same-state frames per `(unit_id, button_event_index)` ("edge detection").

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
- Every NotifyInput frame is emitted at least as `event="input_event"` with:
  - `input_index`, `input_code`, `input_b1`, `input_channel`, `input_value16`
  - `input_mapped_event` (best-effort semantic meaning for `input_code`)

Observed semantic mapping (from captures; Android itself only logs the bytes):
- `input_code 0x01` -> `button_press`
- `input_code 0x02` -> `button_release`
- `input_code 0x09` -> `button_hold`
- `input_code 0x0C` -> `button_release_after_hold`

Wired vs wireless behavior:
- Wired switches may only send NotifyInput frames (no button stream). In that case, the library emits the mapped semantic events (`button_press`, etc).
- Wireless switches usually have both streams; to avoid duplicates, NotifyInput `0x01/0x02` are not emitted as semantic press/release when the button stream was observed for that `(unit_id, button)`. Hold/release-after-hold are still surfaced.

Duplicate handling:
- NotifyInput retransmits are suppressed per `(unit_id, input_index)` by ignoring repeated `input_code` values.

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
- `[CASAMBI_SWITCH_SUMMARY]` frame counts + suppression stats
- `[CASAMBI_UNITSTATE_PARSED]` decoded unit state record fields

Log-driven tests:
- `casambi-bt/tests/test_switch_event_logs.py`
- `casambi-bt/tests/test_unit_state_logs.py`

