# Network Events

`Casambi.registerNetworkEventHandler(callback)` exposes two event sources:

- `source="unit_state"`: changes in fixture-profile control values. The first received
  value is also emitted. Subsequent equal values are suppressed per unit and control.
- `source="invocation"`: each received type 7 invocation, before semantic switch
  merging. `source_stream` distinguishes `button_event`, `notify_input` and other
  invocations. Repeated received frames remain visible in this diagnostic stream.

```python
from CasambiBt import Casambi

casa = Casambi()
casa.registerNetworkEventHandler(handle_event)
# Register before connecting to include the initial state observations.
# Connect through the application's existing credential source.
```

Remove a handler with `unregisterNetworkEventHandler`. Each event contains the
official page's `time`, `timestamp`, `unit`, `name`, `type` and `value` fields.
`time` is the receiving computer's Unix time in milliseconds, not a device event
timestamp. Additional fields explain decoding and transport origin.

## Official implementation and scope

The reference is Casambi Android **3.21.0**, obtained from the vendor's
[official download page](https://app.download.casambi.com/) and
[APK URL](https://standroiddownloadprodwe.blob.core.windows.net/android-apk/casambi_3.21.0.apk).
APK SHA-256:
`504ad959ed94cbe257d1efd966be510a29ad74bb16be991b72d28f6d932014df`.

The official Network events page follows this chain in the decompiled APK:

```text
u22.I / u22.o -> uw0.a -> hm.f -> ea1.p0 -> mi0.a / mi0.b
                                           -> zb1 / formatting helpers
```

`assets/network_events.html` renders the six public fields and filters by text/type.
`hm.f` enumerates fixture controls and emits their changed values. It includes
light controls, presence, lux, battery, temperature and sensor controls. It is a
profile-state view, not a dump of all mesh traffic. The official user-facing
description is in [Performance & Security](https://docs.casambi.com/casambi-app/user-guide/more/performance-security/).

This library preserves the complete public fixture profile in `UnitType.eventProfile`.
Old cached fixture objects without that metadata are refreshed through the public
fixture endpoint. State extraction uses profile bit offsets and little-endian data;
sensor ranges, unit/format overrides and sensor-group selection are retained.
Unlike the official state object's default-filled representation, an unreceived
field in a partial update remains unknown here and emits no invented default event.
Display timestamps use ISO 8601; fixture string localization uses English when
available. App-resource-only translations are not bundled with this library.

The computer is an authenticated BLE/GATT client connected through a Casambi
device. It is not provisioned as a luminaire or mesh relay. Received data can
describe other mesh devices, but neither app source nor this implementation proves
that firmware forwards every mesh message, retransmission or internal operation.

## Type 7 contract

The official receive chain is `lr -> rp.S(cg2)`; `yh1` holds an invocation.
`qa0.A / qa0.b` map the R8 enum and wire opcodes. The R8 enum is one-based;
ButtonEvent wire opcodes remain 29–36 and NotifyInput remains 64–71.

| Field | Encoding |
| --- | --- |
| Header | `flags:u16BE, opcode:u8, origin:u16BE, target:u16BE, age:u16BE` |
| Payload length | `flags & 0x003f`, 0–63 bytes |
| Respond / unique / session | `0x0040 / 0x0080 / 0x0100` |
| Optional origin handle | `0x0200` adds one unsigned byte after age |
| Unnamed boolean flag | `0x0400`, exposed as `flag_0400` |
| Lifetime | `(flags >> 11) & 15` |
| Frame size | 9-byte header, optional handle, then payload; maximum 73 bytes |

`origin >> 8` identifies the emitting node; `origin & 255` is its invocation counter.
It must not be confused with the optional response-correlation `origin_handle`.
For input observations, `target >> 8` identifies the associated device, which can
differ from the emitter. The raw low byte of target selects its target type.
Age and lifetime are retained without converting age into an absolute timestamp.

### ButtonEvent

The official branch requires target type 6, opcode 29–36 and at least 3 payload bytes:

```text
button_event_index = opcode - 29
pressed = bool(payload[0] & 0x80)
param_p = (payload[0] >> 3) & 15
param_s = payload[0] & 7
```

The diagnostic event exposes the raw index, not a guessed physical button label.
It retains the known three-byte input record; any additional bytes remain opaque.

### NotifyInput

The official branch requires target type 18, opcode 64–71 and at least 2 payload bytes:

```text
input_index = opcode - 64
input_code = payload[0]
input_channel = payload[1] & 7
input_value16 = payload[2] + 256 * payload[3]  # when at least 4 bytes exist
```

Missing `input_value16` is `None`, distinct from an explicitly received zero. The
official log prints zero for a missing value. The event retains the known two- or
four-byte record; additional bytes remain opaque.

Every received frame retains its flags, origin, target, optional handle, age,
lifetime, frame offset, transport packet sequence and arrival sequence. Known input
records additionally expose `interpreted_payload_hex`. Other opcodes expose only
metadata and payload length: generic Response, Parameter, SystemService, ExtPacket
and vendor payloads have request-dependent contracts and are not generically
published into the browser or LAN. Truncated streams produce an explicit
`malformed_invocation` diagnostic without dumping the unparsed bytes.

## Legacy switch semantics

`registerSwitchEventHandler` remains the semantic switch API. Its capture-derived
rules are separate from the official receive contract:

- NotifyInput codes `01/02/09/0c` map to press/release/hold/release-after-hold.
- ButtonEvent release bytes are interpreted as duration; 500 ms is this library's
  inference, not a verified official or firmware threshold.
- The four-gang button label mapping is device-specific; raw input indices remain
  authoritative for diagnostics and devices with more inputs.
- Cross-source pairing consumes opposite-source press/release reports within
  three seconds. Complementary losses across rapid clicks can consume a real later
  report. For example, a ButtonEvent release from click A followed by only a
  NotifyInput release from click B is ambiguous without a proven shared action ID.

The Network Events diagnostic bypasses that pairing and preserves both reports.
Its `input` count counts received protocol observations, not unique physical clicks.
The legacy decoder rejects short ButtonEvent records and extends copy suppression
to longer declared lifetimes. Transport receive-counter validation remains an
existing client limitation; app source alone is insufficient to impose a new
wrap/reconnect policy on live devices.

## Investigating missing wireless presses

The demo records receive metadata separately from event observations. This makes
the following boundaries observable without logging keys or arbitrary payloads:

1. EVO notification sequence, wire length, signature result and decrypted packet type.
2. Every decoded type 7 frame before semantic merging, including malformed records.
3. The legacy decoder's emitted count, retransmission suppression and cross-source pairing.
4. Exceptions at the receive queue's recovery boundary, identified by class only.

The status line shows counters for the current connection. Receive metadata is
appended to `network-events.receive.jsonl` with a separate receive-session ID;
`--event-log` changes its basename together with the event history. A continuous
GATT sequence establishes continuity only between the connected node and this
client. It cannot prove that a wireless switch transmitted, or that the node
received and forwarded, every mesh invocation.

Older wireless captures contain ButtonEvent press/release and additional
NotifyInput release/hold from a powered node, but no NotifyInput press for those
wireless actions. Wired captures contain NotifyInput press and release. Thus a
missing wireless ButtonEvent press has no observed second source that can recover
it, while release often has two sources. This describes the captures, not a
guarantee for all devices or firmware. Missing presses are never synthesized from
a release.

In the 2026-10-22 Mac capture before handshake alignment (12:09–12:14,
Europe/Amsterdam), Longpanel-Right produced 25 distinct ButtonEvent presses and
25 NotifyInput releases (24 short, one after hold); four ButtonEvent releases were
absent. Entry produced 12 distinct ButtonEvent presses and 15 releases in both
source streams. Entry's release groups at 12:13:02, 12:13:07 and 12:13:47 had no
corresponding ButtonEvent press in the pre-merge stream. Replaying the saved input
records through the legacy decoder emitted all 25 and 12 received presses,
respectively. The 263 received EVO packets had consecutive sequence numbers and
zero signature failures; none of their type 7 frames was malformed or unknown.
This reproduces missing wireless press observations before semantic decoding,
without establishing whether the switch, mesh path or connected node lost them.

An independent comparison found a concrete EVO handshake discrepancy. Official
Android 3.21.0 `lr.k0` sends `02 | public_key[64] | 0d | 01` for network
connections; `ir.I()` selects the final `01` when the connection has a network
connector. Direct device operations still include `0d`. The former library sent
`02 | public_key[64] | 01`. The network handshake now matches the official bytes.
The formal meaning of `0d` is unknown; there is no firmware-side parser in the APK.
This protocol correction is not evidence that it caused or fixed intermittent
wireless event loss. No additional wireless event CCCD, receive ACK, resend request
or independent advertisement-input parser was found in the inspected app paths.

The aligned handshake was accepted by the real network. In the subsequent
12:16–12:17 Entry capture, 20 distinct NotifyInput releases had 16 ButtonEvent
presses; the missing press groups were 12:16:24, 12:16:32, 12:16:42 and 12:17:18.
All 112 received EVO packets had consecutive sequence numbers, zero signature
failures and zero receive-processing exceptions. NodeInfo identified gateway unit
25. Changing the handshake did not eliminate the reproduced loss. Neither test
identifies whether the switch, the mesh path or gateway forwarding lost the press.

## Local Mac demo

From `casambi-bt/`:

```bash
./.venv/bin/python -m pip install -r scripts/requirements-network-events.txt
./.venv/bin/python scripts/network_events_demo.py \
  --address <cached-network-BLE-MAC>
```

Open `http://127.0.0.1:8765/`. To also serve a specific private LAN interface:

```bash
./.venv/bin/python scripts/network_events_demo.py \
  --address <cached-network-BLE-MAC> \
  --lan-address <Mac-LAN-IPv4>
```

`--lan-address` is repeatable. HTTP and WebSocket share port 8765. The viewer uses
immediate WebSocket push, automatic reconnect and event-ID resume. It updates rows
in place, keeping expanded details and the scrolled reading position. Pausing the
display keeps background capture running.

For a controlled comparison of receive paths, `--gateway-unit <id>` selects a
specific same-network EVO node. The demo matches the configured network endpoint's
short manufacturer-963 advertisement to a node's long advertisement, using the
official `ip.s` layout, then connects to the scanner's BLE device. It checks the
connected NodeInfo unit ID and rejects missing, ambiguous or mismatched selections.
It does not substitute another node silently. The cache remains associated with
the configured network address. This is a diagnostic selection, not a claim that
every node supports equivalent forwarding or that selecting one recovers every
wireless action.

The demo reads the existing local library cache through the normal library key
loader, refreshes public fixture profiles, and performs the normal EVO handshake.
It does not log in to the cloud, persist credentials, change the credential cache,
provision a node, or send lighting/configuration commands. An unavailable or
incompatible cache is reported as a connection failure.

Decoded events are appended to `network-events.jsonl` with owner-only permissions
and retained across restarts. `--event-log` selects another event history file.
This file contains diagnostic events, not network credentials, and is Git-ignored.
The live UI loads the most recent 5,000 observations and renders up to 2,000
matching rows at once. Export includes the complete saved event history, including
events outside the live window. Counts describe received data, not a 42-event cap.

The integration source forwards these events as `casambi_bt_network_event`, with
`entry_id`. This requires a library build containing this API. The demo requires
no HA deployment; source changes do not install themselves into a running HA
instance and no package or integration release is implied.

## Validation

```bash
./.venv/bin/python -m unittest discover -s tests -q
./.venv/bin/python scripts/test_network_events_demo.py -q
```

The tests cover state field boundaries, partial state, sensor conversion, fixture
formats, type 7 headers/flags, input payload length partitions, source preservation,
the complementary-loss sequence, unknown-payload opacity, WebSocket push/resume,
history persistence and export. Existing switch capture regressions exercise
semantic press/hold/release behavior separately.

The completed checks cover 66 library tests, eight demo transport/history/gateway tests
and four HA forwarding/device tests. The event decoder passes targeted lint and
type checks; the demo passes its targeted type check. The touched existing library modules retain their 15 baseline lint
findings without additions; the broader client type check still reports three
pre-existing errors. These are not represented as passing project-wide checks.

On the Mac, the diagnostic connected to the `hou` EVO network, loaded 31 devices,
and received state observations from 29 devices. Actual press/release observations
from device 31 were captured. Browser verification kept
an event expanded while synthetic event count increased from 19 to 48. Local
HTTP/WebSocket requests succeeded on loopback and the selected LAN addresses;
this does not establish that a separate phone has reached the service. Live
presence/lux and every fixture mode have not been physically exercised.

The targeted gateway selection also connected and authenticated through unit 2
(Bedroom Window - L), confirmed NodeInfo unit 2, and received state observations
from 29 network devices. HTTP/WebSocket access remained available on all three
configured interfaces. Wireless press reliability through that selected node has
not yet been tested; this connection success is not a missing-press fix claim.
