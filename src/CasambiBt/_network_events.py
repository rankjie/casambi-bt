"""Profile-driven network events, traced from the official Android 3.21.0 app."""

from __future__ import annotations

import math
import re
from datetime import datetime
from typing import Any

from ._invocation import parse_invocation_stream
from ._unit import Unit

# Wire names from Android 3.21.0 qa0.A / qa0.b (R8 enum ordinals are one-based).
_OPCODE_NAMES: dict[int, str] = {
    0: "FunctionResponse",
    1: "FunctionSetLevel",
    2: "FunctionSetPhysicalLevel",
    3: "FunctionSetTemperature",
    4: "FunctionSetVertical",
    5: "FunctionSetWhite",
    6: "FunctionSetWhiteColorBalance",
    7: "FunctionSetColorHS",
    8: "FunctionSetDimmer0",
    9: "FunctionSetDimmer1",
    10: "FunctionSetDimmer2",
    11: "FunctionSetDimmer3",
    12: "FunctionSetElement0",
    13: "FunctionSetElement1",
    14: "FunctionSetElement2",
    15: "FunctionSetElement3",
    16: "FunctionSceneSwitch",
    17: "FunctionDeleteNode",
    18: "FunctionClearOverheat",
    19: "FunctionTestUnpair",
    20: "FunctionIdentifyInput",
    21: "FunctionVendorMessage0",
    22: "FunctionVendorMessage1",
    23: "FunctionVendorGroupMessage0",
    24: "FunctionVendorGroupMessage1",
    25: "FunctionGetParameter",
    26: "FunctionSetParameter",
    27: "FunctionGetSensor",
    28: "FunctionStartCalibration",
    29: "FunctionButtonEvent0",
    30: "FunctionButtonEvent1",
    31: "FunctionButtonEvent2",
    32: "FunctionButtonEvent3",
    33: "FunctionButtonEvent4",
    34: "FunctionButtonEvent5",
    35: "FunctionButtonEvent6",
    36: "FunctionButtonEvent7",
    37: "FunctionPresence",
    38: "FunctionPresence2",
    39: "FunctionAbsence",
    40: "FunctionRestartNetwork",
    41: "FunctionResumeAutomation",
    42: "FunctionAcquireSwitchSession",
    43: "FunctionExtPacketSend",
    44: "FunctionExtPacketReceive",
    45: "FunctionExecuteDALI",
    46: "FunctionActivateTimers",
    47: "FunctionSetRadioMode",
    48: "FunctionSetState",
    49: "FunctionSetStateBitmap",
    50: "FunctionSetElement4",
    51: "FunctionSetElement5",
    52: "FunctionSetElement6",
    53: "FunctionSetElement7",
    54: "FunctionSetColorXY",
    55: "FunctionIdentifyDevice",
    56: "FunctionSetTwLevel",
    57: "FunctionSetTwLevel0",
    58: "FunctionSetTwLevel1",
    59: "Function59",
    60: "Function60",
    61: "Function61",
    62: "FunctionSetColorRGBW",
    63: "FunctionSystemService",
    64: "FunctionNotifyInput0",
    65: "FunctionNotifyInput1",
    66: "FunctionNotifyInput2",
    67: "FunctionNotifyInput3",
    68: "FunctionNotifyInput4",
    69: "FunctionNotifyInput5",
    70: "FunctionNotifyInput6",
    71: "FunctionNotifyInput7",
    72: "FunctionResponseTrace",
    73: "FunctionNotifyTelemetry",
    74: "FunctionMeshFU",
    75: "Function_Reserved75",
    76: "Function_Reserved76",
    77: "Function_Reserved77",
    144: "FunctionDeviceEvent_0",
    145: "FunctionDeviceEvent_1",
    146: "FunctionDeviceEvent_2",
    147: "FunctionDeviceEvent_3",
    148: "FunctionDeviceEvent_4",
    149: "FunctionDeviceEvent_5",
    150: "FunctionDeviceEvent_6",
    151: "FunctionDeviceEvent_7",
    152: "FunctionTestTrace",
    153: "FunctionTestGpioControl",
}


def input_observation(event: dict[str, Any]) -> dict[str, Any]:
    """Add the previous viewer's four-button labels without changing wire fields.

    The 1/2/3/0 -> 1/2/3/4 display convention is capture-derived, not a universal
    fixture mapping. Keep its provenance and the raw index so other layouts can
    be inspected without inventing a physical button number.
    """
    if event.get("type") != "input":
        return {}
    stream = event.get("source_stream")
    index = (
        event.get("button_event_index")
        if stream == "button_event"
        else event.get("input_index")
    )
    button = (
        ((index + 3) % 4) + 1 if isinstance(index, int) and 0 <= index <= 3 else None
    )
    action = None
    if stream == "button_event" and isinstance(event.get("pressed"), bool):
        action = "press" if event["pressed"] else "release"
    elif stream == "notify_input" and isinstance(code := event.get("input_code"), int):
        action = {1: "press", 2: "release", 9: "hold", 12: "release_after_hold"}.get(
            code
        )
    return {
        "unit_id": event.get("unit"),
        "button": button,
        "button_index": index,
        "button_label_basis": "four_gang_compatibility" if button is not None else None,
        "input_action": action,
    }


def _round(value: float) -> int:
    """Match Java Math.round for the profile's display values."""
    return math.floor(value + 0.5)


def _formatted(value: float, unit: str, decimals: int) -> str:
    """Apply the fixture unit's optional decimal and multiplier format."""
    suffix, _, spec = unit.partition("{")
    precision = re.search(r"\.(\d)", spec)
    multiplier = re.search(r"\*([\d.]+)", spec)
    if precision:
        decimals = int(precision[1])
    if multiplier:
        value *= float(multiplier[1])
    gap = "" if not suffix or suffix.startswith(("%", " ")) else " "
    return f"{value:.{decimals}f}{gap}{suffix}"


def _profile_control(
    control: dict[str, Any], profile: dict[str, Any]
) -> dict[str, Any]:
    """Apply fixture string overrides used by t11.x for units and formats."""
    result = dict(control)
    prefixes = {
        "dimmer": "control_dimmer",
        "rgb": "control_rgb",
        "xy": "control_rgb",
        "temperature": "control_temperature",
        "vertical": "control_vertical",
        "white": "control_white",
        "slider": "control_slider",
        "presence": "sensor_presence",
        "lux": "sensor_lux",
        "sensor": "sensor_tag",
        "ambienttemperature": "sensor_temperature",
        "battery": "sensor_battery",
    }
    strings = profile.get("strings") or {}
    prefix = prefixes.get(control["type"], control["type"])
    key = (control.get("name") or prefix).lower()
    entry = strings.get(key if key.startswith("$") else "$" + key, {})
    unit = entry.get("unit", control.get("unit", ""))
    unit_name, _, inline_format = unit.partition("{")
    fmt = entry.get("format")
    if fmt is None:
        reference = (control.get("name") or prefix) + "_format"
        fmt = strings.get(reference.lower() if reference.startswith("$") else reference)
        if isinstance(fmt, dict):
            fmt = fmt.get("en")
    for _ in range(2):
        translated = strings.get(unit_name.lower())
        if not isinstance(translated, dict) or "en" not in translated:
            break
        unit_name = translated["en"]
    result["unit"] = unit_name + (
        str(fmt) if fmt is not None else "{" + inline_format if inline_format else ""
    )
    return result


def _sensor(raw: int, control: dict[str, Any], length: int) -> tuple[float, str]:
    low, high = control.get("min", 0), control.get("max", 0)
    value_type = control.get("valueType", 0)
    if value_type not in (0, 1):
        raise ValueError(f"Unsupported sensor valueType {value_type}")
    value = low + (raw / ((1 << length) - 1) * (high - low) if value_type == 1 else raw)
    unit = control.get("unit", "")
    suffix = unit.partition("{")[0]
    if value_type == 0:
        integer = int(value)
        if suffix.startswith("|"):
            labels = suffix[1:].split("|")
            return value, ", ".join(
                label
                for bit, label in enumerate(labels)
                if integer & (1 << bit) and label
            )
        if suffix == "%":
            percent = (value - low) / (high - low) * 100 if high > low else value
            return value, _formatted(percent, unit, 1)
        if suffix == "%%":
            return value, _formatted(value, unit.replace("%%", "%", 1), 0)
        if suffix == "hex":
            return value, f"0x{integer:0{((length + 7) // 8) * 2}X}"
        if suffix == "bits":
            return value, "b`" + ":".join(f"{integer:0{max(1, high.bit_length())}b}")
        if suffix == "bytes":
            return value, ":".join(
                f"{(integer >> (i * 8)) & 255:02X}" for i in range((length + 7) // 8)
            )
        if suffix in ("min", "hhhh:min"):
            return value, f"{integer // 60}:{integer % 60:02d}"
        if suffix in ("hhhh:mm:ss", "hhmmss"):
            return (
                value,
                f"{integer // 3600}:{integer // 60 % 60:02d}:{integer % 60:02d}",
            )
        if suffix == "hhhh:mm":
            return value, f"{integer // 3600}:{integer // 60 % 60:02d}"
        if suffix == "hhhh":
            return value, str(integer // 3600)
        if suffix == "hhhh.zz":
            return value, f"{integer / 3600:.2f}"
    decimals = (
        max(0, int(math.log10(abs(((1 << length) - 1) / high))))
        if value_type == 1 and high
        else 0
    )
    return value, _formatted(value, unit, decimals)


class NetworkEventDecoder:
    """Emit a row on first observation and on subsequent control-value changes.

    State fields use little-endian bit offsets from the public fixture profile.
    Unreceived fields in a partial state are left unknown, rather than reporting
    profile defaults as if they had been observed on the mesh.
    """

    def __init__(self) -> None:
        self._last: dict[tuple[int, int, str], Any] = {}

    def reset(self) -> None:
        """Start a fresh observation session after a connection is established."""
        self._last.clear()

    @staticmethod
    def decode_invocations(
        data: bytes,
        *,
        names: dict[int, str],
        packet_sequence: int | None = None,
        arrival_sequence: int | None = None,
        timestamp: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Expose received type 7 frames using Android 3.21.0 rp.S's field layout.

        ButtonEvent and NotifyInput remain distinct observations. No timing-based
        cross-source pairing or inferred long-press threshold is applied here.
        Payload bytes outside the known input fields are intentionally opaque.
        """
        now = timestamp or datetime.now().astimezone()
        frames = parse_invocation_stream(data)
        result = []
        parsed = 0
        for frame in frames:
            target_type = frame.target & 255
            origin_unit = frame.origin >> 8
            target_unit = frame.target >> 8
            unit_id = target_unit if target_type in (6, 18) else origin_unit
            row = {
                "time": int(now.timestamp() * 1000),
                "timestamp": now.isoformat(timespec="milliseconds"),
                "unit": unit_id,
                "name": names.get(unit_id, f"Unit {unit_id}"),
                "type": "invocation",
                "source": "invocation",
                "source_stream": "invocation",
                "packet_type": 7,
                "opcode": frame.opcode,
                "opcode_name": _OPCODE_NAMES.get(
                    frame.opcode, f"Function{frame.opcode}"
                ),
                "invocation_flags": frame.flags,
                "respond": bool(frame.flags & 0x40),
                "unique": bool(frame.flags & 0x80),
                "session": bool(frame.flags & 0x100),
                "flag_0400": bool(frame.flags & 0x400),
                "lifetime": (frame.flags >> 11) & 15,
                "origin": frame.origin,
                "origin_unit_id": origin_unit,
                "origin_counter": frame.origin & 255,
                "origin_handle": frame.origin_handle,
                "target": frame.target,
                "target_type": target_type,
                "age": frame.age,
                "payload_length": frame.payload_len,
                "frame_offset": frame.offset,
                "packet_sequence": packet_sequence,
                "arrival_sequence": arrival_sequence,
            }
            row["value"] = (
                f"{row['opcode_name']} origin=0x{frame.origin:04x} target=0x{frame.target:04x}"
            )
            if target_type == 6 and 29 <= frame.opcode <= 36:
                row["source_stream"] = "button_event"
                if len(frame.payload) < 3:
                    row["type"] = "malformed_invocation"
                    row["value"] = "ButtonEvent payload requires at least 3 bytes"
                else:
                    b0 = frame.payload[0]
                    index, pressed = frame.opcode - 29, bool(b0 & 0x80)
                    row.update(
                        {
                            "type": "input",
                            "button_event_index": index,
                            "pressed": pressed,
                            "param_p": (b0 >> 3) & 15,
                            "param_s": b0 & 7,
                            "interpreted_payload_hex": frame.payload[:3].hex(),
                            "unparsed_payload_length": len(frame.payload) - 3,
                            "value": f"ButtonEvent[{index}] pressed={int(pressed)} P={(b0 >> 3) & 15} S={b0 & 7}",
                        }
                    )
            elif target_type == 18 and 64 <= frame.opcode <= 71:
                row["source_stream"] = "notify_input"
                if len(frame.payload) < 2:
                    row["type"] = "malformed_invocation"
                    row["value"] = "NotifyInput payload requires at least 2 bytes"
                else:
                    code, b1 = frame.payload[:2]
                    size = 4 if len(frame.payload) >= 4 else 2
                    value = (
                        int.from_bytes(frame.payload[2:4], "little")
                        if size == 4
                        else None
                    )
                    index = frame.opcode - 64
                    row.update(
                        {
                            "type": "input",
                            "input_index": index,
                            "input_code": code,
                            "input_b1": b1,
                            "input_channel": b1 & 7,
                            "input_value16": value,
                            "interpreted_payload_hex": frame.payload[:size].hex(),
                            "unparsed_payload_length": len(frame.payload) - size,
                            "value": f"NotifyInput[{index}] channel={b1 & 7} code=0x{code:02x} value16={value}",
                        }
                    )
            row.update(input_observation(row))
            result.append(row)
            parsed = (
                frame.offset
                + 9
                + int(frame.origin_handle is not None)
                + frame.payload_len
            )
        if parsed != len(data):
            result.append(
                {
                    "time": int(now.timestamp() * 1000),
                    "timestamp": now.isoformat(timespec="milliseconds"),
                    "unit": None,
                    "name": "Protocol",
                    "type": "malformed_invocation",
                    "source": "invocation",
                    "source_stream": "invocation",
                    "value": f"Truncated type 7 stream: {len(data) - parsed} trailing bytes at offset {parsed}",
                    "packet_sequence": packet_sequence,
                    "arrival_sequence": arrival_sequence,
                }
            )
        return result

    def decode(
        self, unit: Unit, state: bytes, *, timestamp: datetime | None = None
    ) -> list[dict[str, Any]]:
        """Decode an actual state update, without inspecting network credentials."""
        profile = getattr(unit.unitType, "eventProfile", None)
        if profile is None:
            raise ValueError(f"Fixture {unit.unitType.id} needs a fresh event profile")
        controls = profile["controls"]
        now = timestamp or datetime.now().astimezone()
        result = []
        bits = int.from_bytes(state, "little")
        for index, control in enumerate(controls):
            kind = control["type"]
            offset, length = control["offset"], control["length"]
            if offset < 0 or length < 0 or length > 64:
                raise ValueError(
                    f"Invalid fixture control layout: {kind} {offset}:{length}"
                )
            if not length or offset + length > len(state) * 8:
                continue
            raw = (bits >> offset) & ((1 << length) - 1)
            sensor_control = _profile_control(control, profile)
            if kind == "sensorgroupvalue":
                selected = self._group_sensor(controls, index, bits, len(state))
                if selected is None:
                    continue
                sensor_control = _profile_control(selected, profile)
            decoded = self._value(kind, raw, length, sensor_control, profile)
            if decoded is None:
                continue
            event_type, value, display = decoded
            key = (unit.deviceId, index, kind)
            if key in self._last and self._last[key] == value:
                continue
            self._last[key] = value
            result.append(
                {
                    "time": int(now.timestamp() * 1000),
                    "timestamp": now.isoformat(timespec="milliseconds"),
                    "unit": unit.deviceId,
                    "name": unit.name,
                    "type": event_type,
                    "value": display,
                    "numeric_value": value,
                    "raw_value": raw,
                    "control": control.get("name") or control.get("dataname") or kind,
                    "control_index": index,
                    "offset": offset,
                    "length": length,
                    "source": "unit_state",
                    "state_hex": state.hex(),
                    "sensor_tag": (
                        sensor_control.get("tag") if event_type == "sensor" else None
                    ),
                }
            )
        return result

    @staticmethod
    def _group_sensor(
        controls: list[dict], index: int, bits: int, size: int
    ) -> dict | None:
        for start in range(index - 1, -1, -1):
            group = controls[start]
            if group["type"] != "sensorgroup":
                continue
            offset, length = group["offset"], group["length"]
            if offset + length > size * 8:
                return None
            selected = (bits >> offset) & ((1 << length) - 1)
            if 0 < selected < index - start:
                sensor = controls[start + selected]
                if sensor["type"] != "sensor":
                    raise ValueError(
                        "Sensor group selection refers to a non-sensor control"
                    )
                return dict(sensor)
        return None

    @staticmethod
    def _value(
        kind: str,
        raw: int,
        length: int,
        control: dict[str, Any],
        profile: dict[str, Any],
    ) -> tuple[str, Any, str] | None:
        fraction = raw / ((1 << length) - 1)
        if kind in ("dimmer", "white", "vertical"):
            value = fraction * 100
            return (
                kind,
                value,
                f"{value:.1f} %" if kind != "vertical" else f"{value:.1f}",
            )
        if kind in ("presence", "lux", "overheat", "ballastfailure"):
            return kind, raw, f"{raw} lux" if kind == "lux" else str(raw)
        if kind in ("ambienttemperature", "battery"):
            return kind, raw, f"{raw} {control.get('unit', '').partition('{')[0]}"
        if kind in ("onoff", "button", "pushbutton"):
            value = int(raw != 0)
            return kind, value, str(value)
        if kind == "temperature":
            low, high = control["min"], control["max"]
            if high == low:
                return None
            strings = profile.get("strings") or {}
            if "hidden-kelvins" in strings.get("$control_temperature", {}).get(
                "style", ""
            ):
                value = _round(fraction * 100 + 0.2)
                return kind, value, f"{value} %"
            value = _round(low + fraction * (high - low))
            return kind, value, f"{value} K"
        if kind == "rgb":
            # Network Events uses this fixed 10-bit hue / 8-bit saturation layout.
            hue = ((raw >> 8) & 1023) * 360 / 1023
            saturation = (raw & 255) / 255
            return kind, (hue, saturation), f"H:{min(1, hue):.1f}, S:{saturation:.4f}"
        if kind == "xy":
            mask = (1 << (length // 2)) - 1
            if not mask:
                raise ValueError("XY control requires at least two bits")
            x, y = ((raw >> (length // 2)) & mask) / mask, (raw & mask) / mask
            return kind, (x, y), f"X:{x:.3f}, Y:{y:.3f}"
        if kind == "slider":
            low = control.get("minf", control.get("min", 0))
            high = control.get("maxf", control.get("max", 0))
            value = low + fraction * (high - low)
            span = high - low
            decimals = 3 if span < 2 else 2 if span < 25 else 1 if span < 255 else 0
            return kind, value, _formatted(value, control.get("unit", ""), decimals)
        if kind == "whitecolorbalance":
            a = (
                100
                if fraction <= 0.49506348
                else _round((1 - (fraction - 0.4920635) / 0.5079365) * 100)
            )
            b = _round(fraction * 100 / 0.4920635) if fraction < 0.4890635 else 100
            return kind, (a, b), f"{a}% / {b}%"
        if kind in ("sensor", "sensorgroupvalue"):
            value, display = _sensor(raw, control, length)
            return "sensor", value, display
        # The official event page does not emit data, colorsource or unknown controls.
        return None
