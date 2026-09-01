"""Behavioural tests for switch-event dedup using frames taken from real captures.

Frame bytes are the ones seen in ``testlogs/`` and ``casambi-android/*.log``; only the
origin handle and the arrival time are varied to build multi-click and loss scenarios.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from CasambiBt._switch_events import (  # noqa: E402
    COPY_WINDOW_S,
    SwitchEventStreamDecoder,
)


def frame(
    flags: int, opcode: int, origin: int, target: int, age: int, payload: bytes
) -> bytes:
    """Build one INVOCATION frame (no origin handle byte) as it appears in a type=7 payload."""

    assert flags & 0x3F == len(payload)
    return (
        flags.to_bytes(2, "big")
        + bytes([opcode])
        + origin.to_bytes(2, "big")
        + target.to_bytes(2, "big")
        + age.to_bytes(2, "big")
        + payload
    )


# LEDsGO 4CHANNEL_SW EVO unit 32, button index 1 (label 1), as captured in u32-b1.log.
def wireless_press(handle: int, age: int = 4) -> bytes:
    return frame(0x0803, 0x1E, 0x2000 | handle, 0x2006, age, bytes([0x89, 0x00, 0x02]))


def wireless_release(handle: int, age: int = 15, duration_ticks: int = 0x0E) -> bytes:
    return frame(
        0x0803, 0x1E, 0x2000 | handle, 0x2006, age, bytes([0x09]) + duration_ticks.to_bytes(2, "big")
    )


def notify_input(handle: int, code: int, age: int = 7, *, unit: int = 0x20, index: int = 1) -> bytes:
    """NotifyInput frame for a wireless switch, emitted by mains unit 2 (as in all captures)."""

    return frame(0x1002, 0x40 + index, 0x0200 | handle, (unit << 8) | 0x12, age, bytes([code, 0x08 | index]))


# Scemtec SC-TI-CAS unit 20, input 1, as captured in single_press_wired_unit_20_button_1.log.
def wired_input(handle: int, code: int, age: int = 5) -> bytes:
    return frame(0x1002, 0x41, 0x1400 | handle, 0x1412, age, bytes([code, 0x01]))


def semantic(events: list[dict]) -> list[str]:
    return [e["event"] for e in events if e["event"].startswith("button_")]


class Replay:
    """Feed timed single-frame packets to a decoder and collect events."""

    def __init__(self) -> None:
        self.dec = SwitchEventStreamDecoder()
        self.events: list[dict] = []
        self.copies = 0
        self.paired = 0

    def feed(self, timeline: list[tuple[float, bytes]]) -> list[str]:
        for t, data in sorted(timeline, key=lambda x: x[0]):
            evs, stats = self.dec.decode(data, now=t)
            self.events.extend(evs)
            self.copies += stats.events_suppressed_copies
            self.paired += stats.events_suppressed_paired
        return semantic(self.events)


def wireless_click(t0: float, be_handle: int, ni_handle: int, *, duration_ticks: int = 0x0E) -> list[tuple[float, bytes]]:
    """One wireless click with the copy/NotifyInput timing measured in u32-b1.log."""

    rel = (be_handle + 5) & 0xFF
    return [
        (t0 + 0.000, wireless_press(be_handle, age=4)),
        (t0 + 0.263, wireless_release(rel, age=15, duration_ticks=duration_ticks)),
        (t0 + 0.375, wireless_release(rel, age=26, duration_ticks=duration_ticks)),
        (t0 + 0.412, notify_input(ni_handle, 0x02, age=7)),
        (t0 + 0.975, notify_input(ni_handle, 0x02, age=64)),
    ]


def wired_click(t0: float, handle: int) -> list[tuple[float, bytes]]:
    return [
        (t0 + 0.000, wired_input(handle, 0x01, age=5)),
        (t0 + 0.010, wired_input(handle, 0x01, age=6)),
        (t0 + 0.140, wired_input((handle + 1) & 0xFF, 0x02, age=19)),
    ]


class TestCopySuppression(unittest.TestCase):
    def test_reflood_copies_share_origin_and_are_dropped(self) -> None:
        r = Replay()
        out = r.feed(
            [
                (0.00, wireless_press(0xB1, age=4)),
                (0.03, wireless_press(0xB1, age=7)),
                (0.12, wireless_press(0xB1, age=16)),
            ]
        )
        self.assertEqual(out, ["button_press"])
        self.assertEqual(r.copies, 2)

    def test_same_payload_new_handle_is_a_new_press(self) -> None:
        r = Replay()
        out = r.feed([(0.0, wireless_press(0xB1)), (0.2, wireless_press(0xB9))])
        self.assertEqual(out, ["button_press", "button_press"])
        self.assertEqual(r.copies, 0)

    def test_identical_key_after_window_is_emitted_again(self) -> None:
        # Handle counter wrapped (256 invocations later): must not be treated as a copy.
        r = Replay()
        out = r.feed([(0.0, wireless_press(0xB1)), (COPY_WINDOW_S + 0.5, wireless_press(0xB1))])
        self.assertEqual(out, ["button_press", "button_press"])

    def test_event_id_is_stable_across_copies(self) -> None:
        dec = SwitchEventStreamDecoder()
        first, _ = dec.decode(wireless_press(0xB1, age=4), now=0.0)
        dec2 = SwitchEventStreamDecoder()
        copy, _ = dec2.decode(wireless_press(0xB1, age=16), now=0.0)
        self.assertEqual(first[0]["event_id"], copy[0]["event_id"])


class TestCrossSourcePairing(unittest.TestCase):
    def test_button_release_then_notify_input_release_emits_once(self) -> None:
        r = Replay()
        out = r.feed(wireless_click(0.0, 0xB1, 0xFF))
        self.assertEqual(out, ["button_press", "button_release"])
        self.assertEqual(r.paired, 1)
        release = [e for e in r.events if e["event"] == "button_release"][0]
        self.assertEqual(release["source"], "button_event")
        self.assertEqual(release["press_duration_ms"], 140)
        self.assertFalse(release["held"])

    def test_notify_input_release_before_button_release_emits_once(self) -> None:
        # Seen in another_wireless_single_press.log: NotifyInput (age 10) beat the ButtonEvent (age 32).
        r = Replay()
        out = r.feed(
            [
                (0.000, wireless_press(0xC3, age=5)),
                (0.300, notify_input(0x6A, 0x02, age=10)),
                (0.520, wireless_release(0xCB, age=32, duration_ticks=0x16)),
                (0.600, notify_input(0x6A, 0x02, age=19)),
            ]
        )
        self.assertEqual(out, ["button_press", "button_release"])
        self.assertEqual(r.paired, 1)
        self.assertEqual(r.copies, 1)
        self.assertEqual(r.events[1]["source"], "notify_input")

    def test_long_press_is_press_hold_release_after_hold(self) -> None:
        # long_press_u31-3.log timing: hold notify ~0.8 s after press, release after 2.4 s.
        r = Replay()
        out = r.feed(
            [
                (0.000, wireless_press(0xC0, age=5)),
                (0.155, wireless_press(0xC0, age=15)),
                (0.788, notify_input(0x02, 0x09, age=13)),
                (0.862, notify_input(0x02, 0x09, age=18)),
                (2.404, wireless_release(0xEC, age=2, duration_ticks=0xF2)),
                (4.350, notify_input(0x5B, 0x0C, age=188)),
            ]
        )
        self.assertEqual(out, ["button_press", "button_hold", "button_release_after_hold"])
        release = r.events[-1]
        self.assertEqual(release["press_duration_ms"], 2420)
        self.assertTrue(release["held"])
        self.assertEqual(r.paired, 1)

    def test_notify_input_0c_first_classifies_release_as_after_hold(self) -> None:
        r = Replay()
        out = r.feed(
            [
                (0.0, wireless_press(0x10)),
                (0.7, notify_input(0x20, 0x09)),
                (2.0, notify_input(0x21, 0x0C)),
                (2.1, wireless_release(0x30, duration_ticks=0xC8)),
            ]
        )
        self.assertEqual(out, ["button_press", "button_hold", "button_release_after_hold"])
        self.assertEqual(r.paired, 1)


class TestFastClicks(unittest.TestCase):
    def test_wireless_double_click(self) -> None:
        out = Replay().feed(wireless_click(0.0, 0xB1, 0xFF) + wireless_click(0.35, 0xB9, 0x00))
        self.assertEqual(out, ["button_press", "button_release"] * 2)

    def test_wireless_triple_click_with_reordered_release(self) -> None:
        # release of click 1 (t=0.263) arrives after press of click 2 (t=0.25).
        out = Replay().feed(
            wireless_click(0.0, 0xB1, 0xFF)
            + wireless_click(0.25, 0xB9, 0x00)
            + wireless_click(0.50, 0xC1, 0x01)
        )
        self.assertEqual(out.count("button_press"), 3)
        self.assertEqual(out.count("button_release"), 3)
        self.assertEqual(len(out), 6)

    def test_five_wireless_clicks_inside_copy_window(self) -> None:
        timeline: list[tuple[float, bytes]] = []
        for i in range(5):
            timeline += wireless_click(i * 0.6, (0xB1 + 8 * i) & 0xFF, (0xFF + i) & 0xFF)
        out = Replay().feed(timeline)
        self.assertEqual(out, ["button_press", "button_release"] * 5)

    def test_wired_triple_click(self) -> None:
        out = Replay().feed(wired_click(0.0, 0x03) + wired_click(0.2, 0x0B) + wired_click(0.4, 0x13))
        self.assertEqual(out, ["button_press", "button_release"] * 3)


class TestFrameLossDoesNotSwallowLaterEvents(unittest.TestCase):
    def test_lost_wireless_release_is_recovered_from_notify_input(self) -> None:
        click2 = [x for x in wireless_click(5.0, 0xB9, 0x00) if x[1][2] != 0x1E or x[1][9] & 0x80]
        out = Replay().feed(wireless_click(0.0, 0xB1, 0xFF) + click2 + wireless_click(10.0, 0xC1, 0x01))
        self.assertEqual(out, ["button_press", "button_release"] * 3)

    def test_lost_wireless_press_keeps_next_click_intact(self) -> None:
        click2 = [x for x in wireless_click(5.0, 0xB9, 0x00) if not (x[1][2] == 0x1E and x[1][9] & 0x80)]
        out = Replay().feed(wireless_click(0.0, 0xB1, 0xFF) + click2 + wireless_click(10.0, 0xC1, 0x01))
        self.assertEqual(
            out,
            ["button_press", "button_release", "button_release", "button_press", "button_release"],
        )

    def test_lost_wired_release_keeps_next_press(self) -> None:
        click2 = [x for x in wired_click(5.0, 0x0B) if x[1][9] != 0x02]
        out = Replay().feed(wired_click(0.0, 0x03) + click2 + wired_click(10.0, 0x13))
        self.assertEqual(
            out,
            ["button_press", "button_release", "button_press", "button_press", "button_release"],
        )

    def test_lost_wired_press_keeps_release(self) -> None:
        click2 = [x for x in wired_click(5.0, 0x0B) if x[1][9] != 0x01]
        out = Replay().feed(wired_click(0.0, 0x03) + click2)
        self.assertEqual(out, ["button_press", "button_release", "button_release"])


class TestLabelsAndFields(unittest.TestCase):
    def test_button_event_index_to_label(self) -> None:
        dec = SwitchEventStreamDecoder()
        labels = {}
        for index in range(4):
            evs, _ = dec.decode(
                frame(0x0803, 0x1D + index, 0x2000 | (0x10 + index), 0x2006, 4, bytes([0x80 | (index << 3) | 1, 0, 2])),
                now=0.0,
            )
            labels[index] = evs[0]["button"]
        self.assertEqual(labels, {0: 4, 1: 1, 2: 2, 3: 3})

    def test_wired_input_event_fields(self) -> None:
        dec = SwitchEventStreamDecoder()
        evs, _ = dec.decode(wired_input(0x03, 0x01), now=0.0)
        ev = evs[0]
        self.assertEqual(ev["unit_id"], 20)
        self.assertEqual(ev["button"], 1)
        self.assertEqual(ev["source"], "notify_input")
        self.assertEqual(ev["input_code"], 0x01)
        self.assertEqual(ev["input_channel"], 1)
        self.assertEqual(ev["origin_unit_id"], 20)

    def test_unknown_input_code_is_exposed_as_input_event(self) -> None:
        dec = SwitchEventStreamDecoder()
        evs, _ = dec.decode(wired_input(0x03, 0x77), now=0.0)
        self.assertEqual(evs[0]["event"], "input_event")
        self.assertEqual(evs[0]["input_code"], 0x77)


if __name__ == "__main__":
    unittest.main()
