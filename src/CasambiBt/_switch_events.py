from __future__ import annotations

import logging
import time
from binascii import b2a_hex as b2a
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final

from ._invocation import InvocationFrame, parse_invocation_stream


_BUTTON_EVENT_MIN: Final[int] = 29  # FunctionButtonEvent0
_BUTTON_EVENT_MAX: Final[int] = 36  # FunctionButtonEvent7
_INPUT_EVENT_MIN: Final[int] = 64  # FunctionNotifyInput0
_INPUT_EVENT_MAX: Final[int] = 71  # FunctionNotifyInput7

_TARGET_TYPE_BUTTON: Final[int] = 0x06
_TARGET_TYPE_INPUT: Final[int] = 0x12

_INPUT_CODE_PRESS: Final[int] = 0x01
_INPUT_CODE_RELEASE: Final[int] = 0x02
_INPUT_CODE_HOLD: Final[int] = 0x09
_INPUT_CODE_RELEASE_AFTER_HOLD: Final[int] = 0x0C

# The mesh re-floods an invocation until its lifetime (flags bits 11-14, seconds) expires.
# Every copy carries the same origin/handle, opcode, target and payload; only `age`
# (10 ms ticks) grows. Button/input frames were observed with lifetime <= 2 s.
COPY_WINDOW_S: Final[float] = 3.0

# One physical press/release of a wireless switch is reported by two sources: a ButtonEvent
# from the switch itself and a NotifyInput from a mains-powered unit, in either order and up
# to ~1 s apart. The first one is emitted, the second one is consumed.
PAIR_WINDOW_S: Final[float] = 3.0

# ButtonEvent release frames carry the press duration. Used to classify the release when no
# NotifyInput code (0x02 / 0x0C) arrived first. Observed: short 130-220 ms, long >= 1.9 s.
LONG_PRESS_MS: Final[int] = 500

_SOURCE_BUTTON: Final[str] = "button_event"
_SOURCE_INPUT: Final[str] = "notify_input"


def _guess_button_label_4gang(button_event_index: int) -> int:
    """Map a ButtonEvent/NotifyInput index to the button number shown in the Casambi app.

    Observed on 4-gang switches (matches ``switchConfig.switches[].index + 1``):
    - ButtonEvent1 -> label 1
    - ButtonEvent2 -> label 2
    - ButtonEvent3 -> label 3
    - ButtonEvent0 -> label 4
    """

    if 0 <= button_event_index <= 3:
        return ((button_event_index + 3) % 4) + 1
    return button_event_index


@dataclass(slots=True)
class SwitchDecoderStats:
    frames_total: int = 0
    frames_button: int = 0
    frames_input: int = 0
    frames_ignored: int = 0
    events_emitted: int = 0
    # Mesh re-flood copies of an invocation that was already processed.
    events_suppressed_copies: int = 0
    # NotifyInput/ButtonEvent mirror of a press/release that was already emitted.
    events_suppressed_paired: int = 0


class SwitchEventStreamDecoder:
    """Decode decrypted packet type=7 payload into high-level switch events.

    Two independent mechanisms keep one physical action -> one event:

    1. Copy suppression keyed by invocation identity ``(origin, opcode, target, payload)``.
       ``origin`` is ``unit << 8 | handle`` where ``handle`` is the emitting unit's invocation
       counter, so two distinct presses never share a key while re-flood copies always do.
    2. Cross-source pairing by count: for each ``(unit, button, press|release)`` the first
       report from either source is emitted and the report from the other source is consumed.
       No per-button "currently pressed" state is kept, so a lost or reordered frame can
       never swallow a later real event.
    """

    def __init__(
        self,
        logger: logging.Logger | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._logger = logger or logging.getLogger(__name__)
        self._clock = clock
        # (origin, opcode, target, payload) -> first seen (monotonic seconds)
        self._seen: dict[tuple[int, int, int, bytes], float] = {}
        # (unit_id, button_event_index, kind, source) -> times of emitted events still waiting
        # for their mirror from the other source.
        self._pending: dict[tuple[int, int, str, str], deque[float]] = {}

    def reset(self) -> None:
        self._seen.clear()
        self._pending.clear()

    def decode(
        self,
        data: bytes,
        *,
        packet_seq: int | None = None,
        raw_packet: bytes | None = None,
        arrival_sequence: int | None = None,
        now: float | None = None,
    ) -> tuple[list[dict[str, Any]], SwitchDecoderStats]:
        """Decode one decrypted switch packet payload.

        :param now: Arrival time in seconds on the decoder's clock. Defaults to ``clock()``;
                    tests pass explicit values to replay captures with their real timing.
        """

        if now is None:
            now = self._clock()
        self._expire(now)

        frames = parse_invocation_stream(data, logger=self._logger)
        stats = SwitchDecoderStats(frames_total=len(frames))
        events: list[dict[str, Any]] = []

        for frame in frames:
            ev = self._decode_frame(
                frame,
                now=now,
                data=data,
                packet_seq=packet_seq,
                raw_packet=raw_packet,
                arrival_sequence=arrival_sequence,
                stats=stats,
            )
            if ev is None:
                continue
            events.append(ev)
            stats.events_emitted += 1

        return events, stats

    # ------------------------------------------------------------------ bookkeeping

    def _expire(self, now: float) -> None:
        for key, first_seen in list(self._seen.items()):
            if now - first_seen > COPY_WINDOW_S:
                del self._seen[key]
        for pkey, times in list(self._pending.items()):
            while times and now - times[0] > PAIR_WINDOW_S:
                times.popleft()
            if not times:
                del self._pending[pkey]

    def _is_copy(self, frame: InvocationFrame, now: float) -> bool:
        key = (frame.origin, frame.opcode, frame.target, bytes(frame.payload))
        if key in self._seen:
            return True
        self._seen[key] = now
        return False

    def _claim(self, unit_id: int, index: int, kind: str, source: str, now: float) -> bool:
        """Return True if this press/release should be emitted.

        Returns False (and consumes the pending entry) when the other source already
        emitted the same physical action inside PAIR_WINDOW_S.
        """

        other = _SOURCE_INPUT if source == _SOURCE_BUTTON else _SOURCE_BUTTON
        waiting = self._pending.get((unit_id, index, kind, other))
        if waiting:
            waiting.popleft()
            if not waiting:
                del self._pending[(unit_id, index, kind, other)]
            return False
        self._pending.setdefault((unit_id, index, kind, source), deque()).append(now)
        return True

    # ------------------------------------------------------------------ frames

    def _decode_frame(
        self,
        frame: InvocationFrame,
        *,
        now: float,
        data: bytes,
        packet_seq: int | None,
        raw_packet: bytes | None,
        arrival_sequence: int | None,
        stats: SwitchDecoderStats,
    ) -> dict[str, Any] | None:
        target_type = frame.target & 0xFF

        if (
            target_type == _TARGET_TYPE_BUTTON
            and _BUTTON_EVENT_MIN <= frame.opcode <= _BUTTON_EVENT_MAX
            and frame.payload
        ):
            stats.frames_button += 1
            return self._decode_button_frame(
                frame,
                now=now,
                data=data,
                packet_seq=packet_seq,
                raw_packet=raw_packet,
                arrival_sequence=arrival_sequence,
                stats=stats,
            )

        if (
            target_type == _TARGET_TYPE_INPUT
            and _INPUT_EVENT_MIN <= frame.opcode <= _INPUT_EVENT_MAX
            and len(frame.payload) >= 2
        ):
            stats.frames_input += 1
            return self._decode_input_frame(
                frame,
                now=now,
                data=data,
                packet_seq=packet_seq,
                raw_packet=raw_packet,
                arrival_sequence=arrival_sequence,
                stats=stats,
            )

        stats.frames_ignored += 1
        self._logger.debug(
            "[CASAMBI_INVOKE_IGNORED] packet=%s opcode=0x%02x origin=0x%04x target=0x%04x age=0x%04x flags=0x%04x payload=%s",
            packet_seq,
            frame.opcode,
            frame.origin,
            frame.target,
            frame.age,
            frame.flags,
            b2a(frame.payload),
        )
        return None

    def _decode_button_frame(
        self,
        frame: InvocationFrame,
        *,
        now: float,
        data: bytes,
        packet_seq: int | None,
        raw_packet: bytes | None,
        arrival_sequence: int | None,
        stats: SwitchDecoderStats,
    ) -> dict[str, Any] | None:
        unit_id = (frame.target >> 8) & 0xFF
        index = frame.opcode - _BUTTON_EVENT_MIN
        button = _guess_button_label_4gang(index)

        b0 = frame.payload[0]
        pressed = bool(b0 & 0x80)
        duration_ms: int | None = None
        if not pressed and len(frame.payload) >= 3:
            duration_ms = int.from_bytes(frame.payload[1:3], "big") * 10

        if self._is_copy(frame, now):
            stats.events_suppressed_copies += 1
            self._logger.debug(
                "[CASAMBI_EVENT_SUPPRESS] copy unit=%d button=%d pressed=%s opcode=0x%02x origin=0x%04x age=0x%04x",
                unit_id,
                button,
                pressed,
                frame.opcode,
                frame.origin,
                frame.age,
            )
            return None

        kind = "press" if pressed else "release"
        if not self._claim(unit_id, index, kind, _SOURCE_BUTTON, now):
            stats.events_suppressed_paired += 1
            self._logger.debug(
                "[CASAMBI_EVENT_SUPPRESS] paired unit=%d button=%d %s already reported by NotifyInput origin=0x%04x age=0x%04x",
                unit_id,
                button,
                kind,
                frame.origin,
                frame.age,
            )
            return None

        held = False
        if pressed:
            event = "button_press"
        else:
            held = duration_ms is not None and duration_ms >= LONG_PRESS_MS
            event = "button_release_after_hold" if held else "button_release"

        if self._logger.isEnabledFor(logging.DEBUG):
            self._logger.debug(
                "[CASAMBI_BUTTON_EVENT] packet=%s unit=%d button=%d event=%s duration_ms=%s opcode=0x%02x origin=0x%04x age=0x%04x flags=0x%04x payload=%s",
                packet_seq,
                unit_id,
                button,
                event,
                duration_ms,
                frame.opcode,
                frame.origin,
                frame.age,
                frame.flags,
                b2a(frame.payload),
            )

        ev = self._base_event(
            frame,
            data=data,
            packet_seq=packet_seq,
            raw_packet=raw_packet,
            arrival_sequence=arrival_sequence,
        )
        ev.update(
            {
                "unit_id": unit_id,
                "button": button,
                "event": event,
                "source": _SOURCE_BUTTON,
                "button_event_index": index,
                "param_p": (b0 >> 3) & 0x0F,
                "param_s": b0 & 0x07,
                "press_duration_ms": duration_ms,
                "held": held,
            }
        )
        return ev

    def _decode_input_frame(
        self,
        frame: InvocationFrame,
        *,
        now: float,
        data: bytes,
        packet_seq: int | None,
        raw_packet: bytes | None,
        arrival_sequence: int | None,
        stats: SwitchDecoderStats,
    ) -> dict[str, Any] | None:
        unit_id = (frame.target >> 8) & 0xFF
        index = frame.opcode - _INPUT_EVENT_MIN
        button = _guess_button_label_4gang(index)

        input_code = frame.payload[0]
        input_b1 = frame.payload[1]
        input_channel = input_b1 & 0x07
        input_value16 = (
            int.from_bytes(frame.payload[2:4], "little")
            if len(frame.payload) >= 4
            else None
        )

        if self._is_copy(frame, now):
            stats.events_suppressed_copies += 1
            self._logger.debug(
                "[CASAMBI_EVENT_SUPPRESS] copy unit=%d input=%d code=0x%02x opcode=0x%02x origin=0x%04x age=0x%04x",
                unit_id,
                index,
                input_code,
                frame.opcode,
                frame.origin,
                frame.age,
            )
            return None

        held = False
        if input_code == _INPUT_CODE_PRESS:
            kind: str | None = "press"
            event = "button_press"
        elif input_code == _INPUT_CODE_RELEASE:
            kind = "release"
            event = "button_release"
        elif input_code == _INPUT_CODE_RELEASE_AFTER_HOLD:
            kind = "release"
            event = "button_release_after_hold"
            held = True
        elif input_code == _INPUT_CODE_HOLD:
            kind = None
            event = "button_hold"
            held = True
        else:
            kind = None
            event = "input_event"

        if kind is not None and not self._claim(unit_id, index, kind, _SOURCE_INPUT, now):
            stats.events_suppressed_paired += 1
            self._logger.debug(
                "[CASAMBI_EVENT_SUPPRESS] paired unit=%d button=%d %s already reported by ButtonEvent origin=0x%04x age=0x%04x",
                unit_id,
                button,
                kind,
                frame.origin,
                frame.age,
            )
            return None

        self._logger.debug(
            "[CASAMBI_INPUT_EVENT] packet=%s unit=%d button=%d input=%d event=%s code=0x%02x ch=%d val=%s opcode=0x%02x origin=0x%04x age=0x%04x flags=0x%04x payload=%s",
            packet_seq,
            unit_id,
            button,
            index,
            event,
            input_code,
            input_channel,
            input_value16,
            frame.opcode,
            frame.origin,
            frame.age,
            frame.flags,
            b2a(frame.payload),
        )

        ev = self._base_event(
            frame,
            data=data,
            packet_seq=packet_seq,
            raw_packet=raw_packet,
            arrival_sequence=arrival_sequence,
        )
        ev.update(
            {
                "unit_id": unit_id,
                "button": button,
                "event": event,
                "source": _SOURCE_INPUT,
                "button_event_index": index,
                "input_index": index,
                "input_code": input_code,
                "input_b1": input_b1,
                "input_channel": input_channel,
                "input_value16": input_value16,
                "press_duration_ms": None,
                "held": held,
            }
        )
        return ev

    def _base_event(
        self,
        frame: InvocationFrame,
        *,
        data: bytes,
        packet_seq: int | None,
        raw_packet: bytes | None,
        arrival_sequence: int | None,
    ) -> dict[str, Any]:
        frame_len = 9 + (1 if frame.origin_handle is not None else 0) + frame.payload_len
        payload_hex = b2a(frame.payload)
        return {
            # Back-compat / existing consumers
            "message_type": 0x07,  # decrypted packet type (SwitchEvent)
            "message_position": frame.offset,
            "extra_data": None,
            # INVOCATION fields
            "invocation_flags": frame.flags,
            "opcode": frame.opcode,
            "origin": frame.origin,
            "origin_unit_id": (frame.origin >> 8) & 0xFF,
            "origin_type": frame.origin & 0xFF,
            "target": frame.target,
            "target_type": frame.target & 0xFF,
            "age": frame.age,
            "origin_handle": frame.origin_handle,
            "payload": frame.payload,
            "payload_hex": payload_hex,
            "frame_offset": frame.offset,
            # Diagnostics / correlation. event_id identifies the invocation, so every
            # re-flood copy of one physical action shares it.
            "packet_sequence": packet_seq,
            "arrival_sequence": arrival_sequence,
            "event_id": f"invoke:{frame.origin:04x}:{frame.opcode:02x}:{frame.target:04x}:{payload_hex.decode('ascii')}",
            "raw_packet": b2a(raw_packet) if raw_packet else None,
            "decrypted_data": b2a(data),
            "frame_hex": b2a(data[frame.offset : frame.offset + frame_len]),
            "received_at": time.time(),
        }
