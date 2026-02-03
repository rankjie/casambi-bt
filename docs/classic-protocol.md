# Casambi Classic Bluetooth Protocol

Technical reference for the Classic (non-EVO) Casambi BLE mesh protocol as implemented in `casambi-bt`.
Derived from reverse-engineering the Android app (`casambi-android`) and BLE packet captures.

> **Scope**: This document covers Classic protocol only.
> EVO (protocolVersion &ge; 10 with `keyStore`) uses a different framing and encryption scheme.

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. BLE Service & Characteristic Layout](#2-ble-service--characteristic-layout)
- [3. Connection Establishment](#3-connection-establishment)
- [4. Connection Hash Derivation](#4-connection-hash-derivation)
- [5. Key Management](#5-key-management)
- [6. CMAC Signature Scheme](#6-cmac-signature-scheme)
- [7. TX Packet Structure](#7-tx-packet-structure)
- [8. RX Packet Structure](#8-rx-packet-structure)
- [9. Command Format](#9-command-format)
- [10. Unit State Record Format](#10-unit-state-record-format)
- [11. Payload Dispatch](#11-payload-dispatch)
- [12. Initialization Sequence](#12-initialization-sequence)
- [13. Sequence & Divider Counters](#13-sequence--divider-counters)
- [14. Diagnostic Log Reference](#14-diagnostic-log-reference)
- [Appendix: Packet Examples](#appendix-packet-examples-from-real-device)

---

## 1. Overview

Casambi Classic is a BLE mesh protocol used by older Casambi firmware
(protocolVersion &le; 9, networks without a `keyStore`).
Devices advertise the `CA5A` service UUID and communicate via GATT write/notify
on a small set of characteristics.

The protocol uses AES-CMAC for packet authentication, with two key tiers
(visitor and manager) providing different signature lengths and access levels.

### Classic vs EVO Detection

The protocol mode is determined during connection by reading the auth characteristic:

| First byte of auth read | Mode | Reason |
|:---|:---|:---|
| `0x01` | EVO | NodeInfo packet header |
| Anything else (8+ bytes) | Classic | Connection hash data |
| Read fails / &lt; 8 bytes | Classic (legacy) | Falls back to CA51 hash char |

---

## 2. BLE Service & Characteristic Layout

### Service UUIDs

| Service | UUID | Usage |
|:---|:---|:---|
| Classic (CA5A) | `0000ca5a-0000-1000-8000-00805f9b34fb` | Legacy Classic service |
| FE4D | `0000fe4d-0000-1000-8000-00805f9b34fb` | Shared EVO / Conformant Classic service |

### Characteristics

#### Legacy Classic (CA5A service)

| Name | UUID | Properties | Purpose |
|:---|:---|:---|:---|
| CA51 (Hash) | `0000ca51-...` | read | Connection hash source |
| CA52 (Data) | `0000ca52-...` | read, write, write-no-resp, notify | TX / RX data channel |
| CA53 | `0000ca53-...` | read, write-no-resp, write, indicate | Secondary channel |

#### Conformant Classic (FE4D service)

Conformant Classic maps the legacy characteristics onto the FE4D service:

| Name | UUID | Maps to | Properties |
|:---|:---|:---|:---|
| 0001 (Auth) | `c9ffde48-ca5a-0001-...-8f519b482f77` | CA52 | read, write-no-resp, write, notify |
| 0002 | `c9ffde48-ca5a-0002-...-8f519b482f77` | CA51 | read, write-no-resp, write, notify |
| 0003 | `c9ffde48-ca5a-0003-...-8f519b482f77` | CA53 | read, write-no-resp, write, indicate |

---

## 3. Connection Establishment

### Step-by-step Flow

```text
 Phone/Gateway                          Casambi Device
      |                                       |
      |------- BLE Connect ------------------>|
      |                                       |
      |------- Discover GATT Services ------->|
      |<------ Service List (CA5A / FE4D) ----|
      |                                       |
      |------- Read Auth Char (0001) -------->|  [Conformant path]
      |<------ 8+ bytes (conn hash) ----------|  (first byte != 0x01 -> Classic)
      |                                       |
      |  OR                                   |
      |                                       |
      |------- Read CA51 Char --------------->|  [Legacy path]
      |<------ 8+ bytes (conn hash) ----------|
      |                                       |
      |------- Subscribe Notify (all) ------->|
      |<------ Notify confirmations ----------|
      |                                       |
      |  [State: AUTHENTICATED]               |
      |                                       |
      |  wait ~100ms (notify settle)          |
      |                                       |
      |------- TX: Version Command ---------->|  (visitor key, write-no-resp)
      |                                       |
      |------- TX: Time-Sync Command -------->|  (visitor key, write-with-resp)
      |<------ Write response ----------------|
      |                                       |
      |<------ RX: Full state dump -----------|  (unit state records, 1-3 packets)
      |<------ RX: Network config (0x00) -----|  (netconfig packets)
      |                                       |
      |  [Ready for commands]                 |
```

### Variant Detection

The connection logic probes characteristics in a specific order:

1. **Try auth char read** (`c9ffde48-ca5a-0001-...`):
   - First byte = `0x01` &rarr; **EVO mode** (abort Classic)
   - 8+ bytes, first byte &ne; `0x01` &rarr; **Conformant Classic**
   - Read fails &rarr; try legacy path

2. **Try CA51 read** (`0000ca51-...`):
   - 8+ bytes &rarr; **Legacy Classic**
   - Read fails &rarr; protocol detection failure

### Conformant vs Legacy Summary

| Property | Conformant | Legacy |
|:---|:---|:---|
| Hash source | Auth char (0001) | CA51 |
| Hash source label | `ca52_0001` | `ca51` |
| TX characteristic | Auth char (0001) | CA52 |
| Header format | `[auth][sig][seq][cmd]` | `[sig][cmd]` |
| Time-sync target | 0002 char | CA51 |
| Time-sync cmd byte | `0x07` | `0x0A` |

---

## 4. Connection Hash Derivation

The first 8 bytes read from the hash source form the **connection hash** (`conn_hash8`).
This value is used as the prefix in all CMAC computations.

### Hash Read Format

| Offset | Length | Field | Notes |
|:---:|:---:|:---|:---|
| 0 | 8 | `conn_hash8` | Used in CMAC |
| 8 | 1 | `ext_unit_id` | Optional (if &ge; 13 bytes) |
| 9 | 1 | `ext_flags_lo` | Optional |
| 10 | 1 | `ext_mtu` | Optional |
| 11 | 1 | `ext_proto_ver` | Optional |
| 12 | 1 | `ext_flags_hi` | Optional |

Combined flags (for logging): `(ext_flags_hi << 8) | ext_flags_lo`

### Example

From tester logs:

```text
raw = 70a030c5996cd0bd21a24d0500

conn_hash8      = 70 a0 30 c5 99 6c d0 bd   (bytes 0-7)
ext_unit_id     = 0x21 = 33                   (byte 8)
ext_flags_lo    = 0xa2                        (byte 9)
ext_mtu         = 0x4d = 77                   (byte 10)
ext_proto_ver   = 0x05 = 5                    (byte 11)
ext_flags_hi    = 0x00                        (byte 12)
combined_flags  = 0x00a2
```

---

## 5. Key Management

Classic networks provide two AES-128 keys from the cloud API:

| Key | Auth Level | Sig Length | Access |
|:---|:---:|:---:|:---|
| Visitor | `0x02` | 4 bytes | Read states, send basic commands |
| Manager | `0x03` | 16 bytes | Full control, configuration |

### Key Source

Keys are retrieved from the cloud network profile JSON:

```json
{
  "network": {
    "visitorKey": "aabbccdd11223344aabbccdd11223344",
    "managerKey": "00112233445566778899aabbccddeeff"
  }
}
```

Networks with a `keyStore` field are EVO (different key derivation).

### Key Selection for TX

| Preference | Resolution |
|:---|:---|
| `auto` | Manager if available and `isManager()`, else visitor, else manager, else unsigned |
| `visitor` | Visitor key with auth=`0x02`, sig\_len=4 |
| `manager` | Manager key with auth=`0x03`, sig\_len=16 |

Bootstrap packets (version, time-sync) always use the **visitor** key.

---

## 6. CMAC Signature Scheme

All signed packets use AES-CMAC ([RFC 4493](https://datatracker.ietf.org/doc/html/rfc4493))
with the connection hash as input prefix.

### CMAC Input

```text
CMAC_input = conn_hash8 || payload_to_sign
```

Where `payload_to_sign` differs by header mode:

| Mode | `payload_to_sign` |
|:---|:---|
| Conformant | `seq(2 bytes, big-endian) \|\| command_bytes` |
| Legacy | `command_bytes` |

### Signature Extraction

```python
full_mac  = AES_CMAC(key, conn_hash8 || payload_to_sign)  # 16 bytes
signature = full_mac[0 : sig_len]                           # truncated
```

| Auth Level | sig\_len | Key |
|:---|:---:|:---|
| `0x02` (visitor) | 4 | visitor key |
| `0x03` (manager) | 16 | manager key |

### Verification (RX)

```python
expected = AES_CMAC(key, conn_hash8 || cmac_input)[0 : sig_len]
verified = (expected == received_sig)
```

---

## 7. TX Packet Structure

### Conformant Header

| Offset | Length | Field |
|:---:|:---:|:---|
| 0 | 1 | `auth_level` &mdash; `0x02` = visitor, `0x03` = manager |
| 1 | N | `signature` &mdash; N = 4 (visitor) or 16 (manager) |
| 1+N | 2 | `sequence` &mdash; big-endian, `0x0001`..`0xFFFF` |
| 3+N | ... | `command_bytes` &mdash; see [Command Format](#9-command-format) |

**Total**: `1 + sig_len + 2 + cmd_len` bytes

### Legacy Header

| Offset | Length | Field |
|:---:|:---:|:---|
| 0 | N | `signature` &mdash; N = 4 or 16 (tried both on RX) |
| N | ... | `command_bytes` |

**Total**: `sig_len + cmd_len` bytes

### Example: Conformant Visitor TX

```text
Packet: 02  293a8e21  0001  00010b
        |   |         |     |
        |   |         |     +-- command: version (3 bytes)
        |   |         +------- seq: 0x0001
        |   +----------------- sig: 4 bytes (visitor)
        +--------------------- auth: 0x02 (visitor)

CMAC input: conn_hash8 || 00 01 || 00 01 0b
```

### Example: Conformant Manager TX

```text
Packet: 03  d94592e2779b4541621776d5a8ead0f3  0003  f5c7b81dc8...
        |   |                                  |     |
        |   |                                  |     +-- command bytes
        |   |                                  +-------- seq: 0x0003
        |   +------------------------------------------- sig: 16 bytes (manager)
        +----------------------------------------------- auth: 0x03 (manager)
```

---

## 8. RX Packet Structure

Incoming notifications are parsed through a **candidate scoring system** because
Classic devices and firmware variants may send conformant, legacy, or unsigned (raw) frames.

> **Observed (Android v3.16)**: The Classic "unit state stream" notifications are
> delivered as **raw bytes** (no CMAC header) and parsed directly as unit records.
> `casambi-bt` keeps CMAC-capable parsing for robustness and for other potential variants.

### Candidate Generation

Each received frame produces up to 4 candidates:

| Candidate | Parsing | When used |
|:---|:---|:---|
| Conformant | Strip `[auth][sig][seq]`, verify CMAC | If auth byte is `0x02` or `0x03` |
| Legacy (4-byte sig) | Strip `[sig:4]`, verify CMAC | Try both keys |
| Legacy (16-byte sig) | Strip `[sig:16]`, verify CMAC | Try both keys |
| Raw | Entire frame = payload | Always generated |

### Scoring

| Condition | Score |
|:---|:---:|
| CMAC verified (`verified=True`) | **100** |
| Plausible payload, unverifiable (`verified=None`) | **50** |
| Plausible payload, CMAC failed (`verified=False`) | **20** |
| Implausible payload | **0** (rejected) |

The highest-scoring candidate wins.
Ties are broken by: preferred mode first, then longer signature.

### Plausibility Check

A payload is **plausible** if any of these conditions hold:

1. **EVO packet type**: `payload[0]` is `6` (UnitState), `7` (SwitchEvent), or `9` (NetworkConfig)
2. **Classic command record**: first byte encodes a valid record length:
   `rec_len = (payload[0] - 239) & 0xFF`, and `2 <= rec_len <= len(payload)`
3. **Classic control byte** *(Classic mode only)*: `payload[0]` is `0x00` (netconfig) or `0xFF` (log)
4. **Classic unit state stream** *(Classic mode only)*: `_walk_classic_records(payload)` succeeds &mdash;
   walks entire payload as unit state records with exact byte consumption

### Record Walk Validation

The `_walk_classic_records` function validates that a byte sequence is a complete
unit state record stream:

```python
pos = 0
count = 0

while pos + 3 <= len(data):
    unit_id   = data[pos]
    flags     = data[pos + 1]
    state_len = flags & 0x0F

    if unit_id == 0 or unit_id == 255:
        return False                # control bytes, not valid in stream

    pos += 2

    if unit_id == 0xF0:             # command response
        if state_len < 2:
            return False
        pos += state_len
    else:                           # normal unit record
        has_extra1 = (flags & 0x20) != 0
        has_extra2 = (flags & 0x40) != 0
        pos += int(has_extra1) + int(has_extra2) + state_len

    if pos > len(data):
        return False
    count += 1

return count >= 1 and pos == len(data)
```

### Example: 4-byte Short Packet

```text
RX: 1d 82 fc 03

Walk:
  unit_id   = 0x1d (29)
  flags     = 0x82 -> state_len=2, online=1, no extras
  pos: 0 -> 2 -> 2+0+0+2 = 4
  count=1, pos=4 == len(4)  ->  plausible

Candidate: mode=raw, score=50
Parsed:    unit 29, online, state=fc03
```

---

## 9. Command Format

Commands use a length-prefixed record format.
Ground truth: `casambi-android u1.C1753e`.

### Record Layout

| Offset | Length | Field | Notes |
|:---:|:---:|:---|:---|
| 0 | 1 | `encoded_length` | `(record_len + 239) & 0xFF` |
| 1 | 1 | `type_flags` | `ordinal(0x3F) \| div_flag(0x40) \| target_flag(0x80)` |
| 2 | 1 | `div` | If bit 6 set (always in this impl) |
| 3 | 1 | `target_id` | If bit 7 set; omitted for broadcast |
| next | 1 | `lifetime` | TTL for mesh forwarding (0&ndash;255) |
| next | ... | `payload` | Command-specific data |

### Type Flags Breakdown

| Bit | Mask | Meaning |
|:---:|:---:|:---|
| 7 | `0x80` | Target unit present |
| 6 | `0x40` | Div / counter present (always set) |
| 5&ndash;0 | `0x3F` | Command ordinal |

### Command Ordinals

| Ordinal | Name | Usage |
|:---:|:---|:---|
| 1 | Version | Bootstrap: declare protocol version |
| 7 | Control / Time-sync | Unit control (ONOFF, dim) / time-sync (conformant) |
| 10 | Time-sync (legacy) | Time-sync for legacy header mode |

### Example: Turn On Unit 29

```text
Command bytes: f5 c7 b8 1d c8 ...
               |  |  |  |  |
               |  |  |  |  +-- lifetime  (200 = 0xC8)
               |  |  |  +----- target_id (29 = 0x1D)
               |  |  +-------- div       (0xB8 = 184)
               |  +----------- type_flags: 0xC7 = ordinal 7 | 0x40 | 0x80
               +-------------- encoded_length: (6+239) & 0xFF = 0xF5

Decoded:
  record_len = (0xF5 - 239) & 0xFF = 6
  ordinal    = 0xC7 & 0x3F = 7 (control)
  has_div    = (0xC7 & 0x40) != 0  ->  True
  has_target = (0xC7 & 0x80) != 0  ->  True
  div        = 184
  target     = 29
  lifetime   = 200
  payload    = remaining bytes (ON/OFF + dim level)
```

---

## 10. Unit State Record Format

Unit state records are streamed in the payload after dispatch.
Ground truth: `casambi-android a1.c.V()`.

### Record Layout

| Offset | Length | Field | Notes |
|:---:|:---:|:---|:---|
| 0 | 1 | `unit_id` | Unit address |
| 1 | 1 | `flags` | See [Flags Byte](#flags-byte) |
| 2 | 0&ndash;1 | `extra1` | Present if flags bit 5 set |
| next | 0&ndash;1 | `extra2` | Present if flags bit 6 set |
| next | N | `state` | N = `flags & 0x0F` |

### Flags Byte

| Bit | Mask | Meaning |
|:---:|:---:|:---|
| 7 | `0x80` | Online (1 = online, 0 = offline) |
| 6 | `0x40` | `extra2` present |
| 5 | `0x20` | `extra1` present |
| 4 | `0x10` | Priority 14 |
| 3&ndash;0 | `0x0F` | `state_len` (0&ndash;15 bytes) |

### Special Unit IDs

| ID | Meaning | Record Format |
|:---|:---|:---|
| `0x00` | Network config marker | Not a unit record (dispatch level) |
| `0xF0` | Command response | `cmd_id(1) + seq(1) + payload(state_len - 2)` |
| `0xFF` | Log marker | Not a unit record (dispatch level) |
| `0x01`&ndash;`0xFE` (except `0xF0`) | Normal unit | Standard record format |

### Example: Single Unit Record

```text
Packet: 1d a2 ff 00 00

unit_id = 0x1D (29)
flags   = 0xA2 = 0b_1_0_1_0_0010
                    | | | |    |
                    | | | |    +--- state_len = 2
                    | | | +------- priority 14 = no
                    | | +--------- extra1 present = yes
                    | +----------- extra2 present = no
                    +------------- online = yes

extra1  = 0xFF (255)
state   = 00 00

Interpretation: unit 29, online, 2-byte state (off), extra1=255
```

### Example: Multi-Record Stream (Initial Dump)

```text
Packet (71 bytes):

01 a2 ff 00 00     unit=1,  flags=0xA2, online, extra1=0xFF, state=0000
02 c2 01 ff ff     unit=2,  flags=0xC2, online, extra1=0x01, extra2=0xFF, state=...
03 c2 07 60 02     unit=3,  flags=0xC2, online, extra1=0x07, extra2=0x60, state=02
04 a2 ff 00 00     unit=4,  flags=0xA2, online, extra1=0xFF, state=0000
07 e2 a3 10 00 00  unit=7,  flags=0xE2, online, extra1=0xA3, extra2=0x10, state=0000
08 e2 ff 10 00 00  unit=8,  flags=0xE2, online, extra1=0xFF, extra2=0x10, state=0000
09 e2 ff 10 00 00  unit=9,  flags=0xE2, online, extra1=0xFF, extra2=0x10, state=0000
0a 82 e8 02        unit=10, flags=0x82, online, state=E802
0b a2 ff 00 00     unit=11, flags=0xA2, online, extra1=0xFF, state=0000
0d 03 08 00 00     unit=13, flags=0x03, OFFLINE, state=080000
...
```

### Command Response Record (`0xF0`)

| Offset | Length | Field | Notes |
|:---:|:---:|:---|:---|
| 0 | 1 | `0xF0` | Marker |
| 1 | 1 | `flags` | `state_len` in lower nibble (must be &ge; 2) |
| 2 | 1 | `cmd_id` | |
| 3 | 1 | `seq_byte` | |
| 4 | N&minus;2 | `response_payload` | N = `state_len` |

Ground truth: `casambi-android a1.c.java:257-260`

---

## 11. Payload Dispatch

After RX parsing selects the best candidate, the payload is routed by its first byte.

### Dispatch Table

| First Byte | Handler | Description |
|:---:|:---|:---|
| `0x00` | *(logged, ignored)* | Network configuration data |
| `0xFF` | *(logged, ignored)* | Log / diagnostic message |
| Any other | `_parseClassicUnitStates(payload)` | Unit state record stream |

> **Note**: The entire payload is passed to `_parseClassicUnitStates`,
> including the first byte which is the first `unit_id` in the record stream.

### Contrast with EVO Dispatch

EVO uses explicit packet type bytes:

| Byte | EVO Meaning |
|:---:|:---|
| 6 | UnitState |
| 7 | SwitchEvent |
| 9 | NetworkConfig |

Classic reuses the first byte as a `unit_id` (1&ndash;239) or control marker (0, 255).

---

## 12. Initialization Sequence

After connection and notify subscription, two bootstrap packets are sent.

### Step 1: Version Packet

| Field | Value |
|:---|:---|
| **Timing** | After subscribing to notifications (`casambi-bt` waits ~100 ms for notify setup to settle) |
| **Key** | Visitor (`auth_level=0x02`, `sig_len=4`) |
| **Write** | Write-without-response |
| **Target** | TX characteristic (auth char or CA52) |

```text
Payload: 00 01 0b
         |  |  |
         |  |  +-- 0x0B = 11 (version minor)
         |  +----- 0x01      (version major)
         +-------- 0x00      (marker)
```

### Step 2: Time-Sync Packet

| Field | Value |
|:---|:---|
| **Timing** | Sent after the version write completes (sequential; Android triggers time-sync after version completion) |
| **Key** | Visitor (`auth_level=0x02`, `sig_len=4`) |
| **Write** | Write-with-response |
| **Target** | 0002 char (conformant) or CA51 (legacy) |

**Payload structure (27 bytes):**

| Offset | Len | Field | Example |
|:---:|:---:|:---|:---|
| 0 | 1 | `cmd_byte` | `0x07` (conformant) or `0x0A` (legacy) |
| 1 | 2 | `year` (BE) | `07 EA` = 2026 |
| 3 | 1 | `month` | `02` |
| 4 | 1 | `day` | `03` |
| 5 | 1 | `hour` | `16` = 22 |
| 6 | 1 | `minute` | `0B` = 11 |
| 7 | 1 | `second` | `10` = 16 |
| 8 | 2 | `utc_offset_min` (BE, signed) | `00 3C` = +60 |
| 10 | 4 | `dst_transition` (BE) | `00 00 00 00` |
| 14 | 1 | `dst_change` | `00` (no DST) |
| 15 | 3 | `longitude` (BE) | Lower 3 bytes of `round(lon * 65536)` |
| 18 | 3 | `latitude` (BE) | Lower 3 bytes of `round(lat * 65536)` |
| 21 | 2 | *(reserved)* | `00 00` |
| 23 | 3 | `millis` (BE) | Elapsed ms |
| 26 | 1 | `longitude` high byte | `lon >> 24` |

Location is encoded as 32-bit fixed-point (`value * 65536`), split across
bytes 15&ndash;17 (lower 3 bytes) and byte 26 (high byte) for longitude.

### Post-Init RX

After initialization, the device sends:

1. **Full state dump** &mdash; 1&ndash;3 large packets (49&ndash;72 bytes each) containing unit state records for all units
2. **Network config packets** &mdash; Multiple packets starting with `0x00`, containing unit-to-group mappings and topology
3. **Individual updates** &mdash; Short packets (4&ndash;5 bytes) for any subsequent state changes

---

## 13. Sequence & Divider Counters

### TX Sequence Number

| Property | Value |
|:---|:---|
| Width | 16-bit, big-endian |
| Range | `0x0001` &ndash; `0xFFFF` (0 is skipped) |
| Scope | Per-connection, reset on reconnect |
| Usage | Included in conformant header and CMAC input |

```python
seq = (seq + 1) & 0xFFFF
if seq == 0:
    seq = 1
```

### Command Divider

| Property | Value |
|:---|:---|
| Width | 8-bit |
| Range | 1 &ndash; 255 (0 is skipped) |
| Scope | Per-connection, initialized to random byte |
| Usage | Byte 2 of every command record |

```python
div += 1
if div == 0 or div > 255:
    div = 1
```

The divider serves as a per-command counter/nonce within the connection,
distinct from the per-packet sequence number.

---

## 14. Diagnostic Log Reference

Key log tags emitted during Classic operation.

### Connection Phase

| Tag | Level | Description |
|:---|:---:|:---|
| `CASAMBI_PROTOCOL_PROBE` | WARN | Final protocol detection result with all probe data |
| `CASAMBI_CLASSIC_SELECTED` | WARN | Selected variant, UUIDs, header mode |
| `CASAMBI_CLASSIC_CONN_HASH` | WARN | Hash bytes read from device |
| `CASAMBI_CLASSIC_CONN_HASH_EXT` | WARN | Extended hash fields (unitId, flags, MTU, proto) |
| `CASAMBI_CLASSIC_KEYS` | WARN | Visitor / manager key availability |
| `CASAMBI_CLASSIC_GATT_CHAR` | WARN | Each GATT characteristic found |
| `CASAMBI_CLASSIC_GATT_SUB` | WARN | Notify subscription confirmation |
| `CASAMBI_CLASSIC_GATT_ENUM` | WARN | Summary of all subscribed UUIDs |

### Initialization

| Tag | Level | Description |
|:---|:---:|:---|
| `CASAMBI_CLASSIC_INIT` | WARN | Version and time-sync send attempts |
| `CASAMBI_CLASSIC_TX` | WARN | Detailed TX packet breakdown |
| `CLASSIC_DIAG_TX_RESULT` | WARN | TX write result (ok / error) |

### Data Reception

| Tag | Level | Description |
|:---|:---:|:---|
| `CLASSIC_DIAG_RX` | DEBUG | Raw frame received (counter, handle, hex prefix) |
| `CLASSIC_DIAG_RX_PARSE` | DEBUG | Parsing result: mode, verified, score, payload\_len |
| `CASAMBI_CLASSIC_RX` | DEBUG | Selected candidate details (rate-limited) |
| `CASAMBI_CLASSIC_RX_PARSE_FAIL` | DEBUG | No candidate could be generated (rate-limited) |
| `CASAMBI_CLASSIC_RX_UNPLAUSIBLE` | DEBUG | Payload rejected by all plausibility checks (rate-limited) |
| `CASAMBI_CLASSIC_RX_MODE` | DEBUG | Auto-correcting header mode (rate-limited) |
| `CASAMBI_CLASSIC_RX_STATS` | DEBUG | 60-second aggregate: verified / unverifiable / raw counts |
| `CASAMBI_CLASSIC_RX_KIND` | DEBUG | First few payloads per kind (type6 / cmdstream / etc.) |

### State Parsing

| Tag | Level | Description |
|:---|:---:|:---|
| `CASAMBI_CLASSIC_DISPATCH` | DEBUG | Dispatch decision (type\_byte, len, hex) |
| `CASAMBI_CLASSIC_NETCONFIG` | DEBUG | Network config payload (first\_byte = 0) |
| `CASAMBI_CLASSIC_LOG` | DEBUG | Log payload (first\_byte = 255) |
| `CASAMBI_CLASSIC_STATE_PARSED` | DEBUG | Each parsed unit state record |
| `CASAMBI_CLASSIC_CMD` | DEBUG | Parsed command record from stream |
| `CASAMBI_CLASSIC_CMD_RESP` | DEBUG | Command response (unit\_id = `0xF0`) |

---

## Appendix: Packet Examples from Real Device

### Full State Dump (RX #1, 72 bytes)

```text
01 a2 ff 00 00     unit=1,  flags=0xA2, online, extra1=0xFF, state=0000
02 c2 01 ff ff     unit=2,  flags=0xC2, online, extra1=0x01, extra2=0xFF, state=...
03 c2 07 60 02     unit=3,  flags=0xC2, online, extra1=0x07, extra2=0x60, state=02
04 a2 ff 00 00     unit=4,  flags=0xA2, online, extra1=0xFF, state=0000
07 e2 a3 10 00 00  unit=7,  flags=0xE2, online, extra1=0xA3, extra2=0x10, state=0000
08 e2 ff 10 00 00  unit=8,  flags=0xE2, online, extra1=0xFF, extra2=0x10, state=0000
09 e2 ff 10 00 00  unit=9,  flags=0xE2, online, extra1=0xFF, extra2=0x10, state=0000
0a 82 e8 02        unit=10, flags=0x82, online, state=E802
0b a2 ff 00 00     unit=11, flags=0xA2, online, extra1=0xFF, state=0000
0d 03 08 00 00     unit=13, flags=0x03, OFFLINE, state=080000
...
```

### Short Status Update (RX #9, 4 bytes)

```text
1d 82 fc 03

unit_id = 29
flags   = 0x82  ->  online, state_len=2, no extras
state   = fc 03 ->  0x03FC = 1020 (full brightness)
```

### Turn-Off Response (RX #8, 5 bytes)

```text
1d a2 ff 00 00

unit_id = 29
flags   = 0xA2  ->  online, state_len=2, extra1 present
extra1  = 0xFF
state   = 00 00 ->  off
```

### Dimming Updates from Casambi App (RX #15&ndash;#17)

```text
1d 82 54 02     unit=29, state=0x0254 = 596   (~58% brightness)
1d 82 94 03     unit=29, state=0x0394 = 916   (~90% brightness)
1d 82 fc 03     unit=29, state=0x03FC = 1020  (100% brightness)
```

### Conformant TX: ONOFF Command

```text
Full packet (25 bytes):
03  d94592e2779b4541621776d5a8ead0f3  0003  f5c7b81dc8

Breakdown:
03                                  auth = manager
d94592e2779b4541621776d5a8ead0f3    sig  = 16-byte CMAC prefix
0003                                seq  = 3
f5 c7 b8 1d c8                     command bytes:
  f5 = (6+239) & 0xFF  ->  record_len = 6
  c7 = ordinal 7 | 0x40 | 0x80 (div + target present)
  b8 = div (184)
  1d = target (unit 29)
  c8 = lifetime (200)
  (remaining = ON payload)
```
