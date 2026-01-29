from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

# Allow tests to run without installing the package.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from CasambiBt._client import CasambiClient, IncommingPacketType  # noqa: E402
from CasambiBt._unit import Unit, UnitControl, UnitControlType, UnitType  # noqa: E402


_HEX_RE = re.compile(r"b'([0-9a-fA-F]+)'")


def _extract_unitstate_payloads_from_log(log_path: Path) -> list[bytes]:
    """Extract decrypted type=6 payloads (without the leading type byte) from a log file."""
    payloads: list[bytes] = []
    text = log_path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        # Common format in captured logs:
        #   Decrypted package: b'06...'
        if "Decrypted package:" in line:
            m = _HEX_RE.search(line)
            if not m:
                continue
            decrypted = bytes.fromhex(m.group(1))
            if decrypted and decrypted[0] == 0x06:
                payloads.append(decrypted[1:])
            continue
    return payloads


class _DummyNetwork:
    protocolVersion = 10


class TestUnitStateParsing(unittest.TestCase):
    def test_unitstate_parse_matches_android_layout(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        log_path = repo_root / "testlogs" / "another_wireless_single_press.log"
        payloads = _extract_unitstate_payloads_from_log(log_path)
        self.assertGreater(len(payloads), 0, "No unit state payloads extracted from log.")

        parsed: list[dict] = []

        def cb(pt: IncommingPacketType, data: dict) -> None:
            if pt == IncommingPacketType.UnitState:
                parsed.append(data)

        c = CasambiClient("00:00:00:00:00:00", cb, lambda: None, _DummyNetwork())
        c._parseUnitStates(payloads[0])

        self.assertEqual(len(parsed), 1)
        u = parsed[0]

        # From log: decrypted packet b'061f1020d5d50015'
        self.assertEqual(u["id"], 31)
        self.assertEqual(u["flags"], 0x10)
        self.assertEqual(u["prio"], 0)
        self.assertEqual(u["state_len"], 3)
        self.assertEqual(u["extra_byte"], 0xD5)
        self.assertAlmostEqual(u["extra_float"], 0xD5 / 255.0)
        self.assertEqual(u["state"].hex(), "d50015")
        self.assertFalse(u["online"])
        self.assertFalse(u["on"])
        self.assertIsNone(u["con"])
        self.assertIsNone(u["sid"])

    def test_unitstate_unknown_controls_are_preserved(self) -> None:
        # The wireless switch unit state bytes in logs are 3 bytes: d5 00 15
        # and the current unit type description marks both controls as UNKNOWN.
        ut = UnitType(
            id=13180,
            model="switch",
            manufacturer="unknown",
            mode="",
            stateLength=3,
            controls=[
                UnitControl(
                    type=UnitControlType.UNKOWN,
                    offset=0,
                    length=8,
                    default=0,
                    readonly=True,
                ),
                UnitControl(
                    type=UnitControlType.UNKOWN,
                    offset=8,
                    length=16,
                    default=0,
                    readonly=True,
                ),
            ],
        )
        u = Unit(
            _typeId=13180,
            deviceId=31,
            uuid="dummy",
            address="00:00:00:00:00:00",
            name="dummy",
            firmwareVersion="0",
            unitType=ut,
        )
        u.setStateFromBytes(bytes.fromhex("d50015"))

        self.assertIsNotNone(u.state)
        assert u.state is not None

        # (offset_bits, length_bits, value_int)
        self.assertEqual(
            u.state.unknown_controls,
            [(0, 8, 0xD5), (8, 16, 0x1500)],
        )
        self.assertEqual(u.state.raw_state, bytes.fromhex("d50015"))
        self.assertEqual(u.state.as_dict()["raw_state_hex"], "d50015")


if __name__ == "__main__":
    unittest.main()

