from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Allow tests to run without installing the package.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from CasambiBt._unit import Unit, UnitControl, UnitControlType, UnitType  # noqa: E402


class TestPartialStateMerge(unittest.TestCase):
    def test_merge_preserves_other_fields_with_offsets(self) -> None:
        # Build a simple unit state layout:
        # - byte 0: dimmer (8 bits)
        # - byte 1: white (8 bits)
        ut = UnitType(
            id=1,
            model="test",
            manufacturer="test",
            mode="",
            stateLength=2,
            controls=[
                UnitControl(
                    type=UnitControlType.DIMMER,
                    offset=0,
                    length=8,
                    default=0,
                    readonly=False,
                ),
                UnitControl(
                    type=UnitControlType.WHITE,
                    offset=8,
                    length=8,
                    default=0,
                    readonly=False,
                ),
            ],
        )

        u = Unit(
            _typeId=ut.id,
            deviceId=1,
            uuid="dummy",
            address="00:00:00:00:00:00",
            name="dummy",
            firmwareVersion="0",
            unitType=ut,
        )

        # Initial partial update at offset 0 (dimmer only).
        u.setStateFromBytes(bytes([0x33]), byte_offset=0)
        assert u.state is not None
        self.assertEqual(u.state.dimmer, 0x33)
        self.assertEqual(u.state.white, 0x00)

        # Partial update at offset 1 (white only) should preserve dimmer.
        u.setStateFromBytes(bytes([0x99]), byte_offset=1)
        assert u.state is not None
        self.assertEqual(u.state.dimmer, 0x33)
        self.assertEqual(u.state.white, 0x99)

        # Partial update at offset 0 should preserve white.
        u.setStateFromBytes(bytes([0x10]), byte_offset=0)
        assert u.state is not None
        self.assertEqual(u.state.dimmer, 0x10)
        self.assertEqual(u.state.white, 0x99)

    def test_rgb_decoding_prefers_raw_on_classic_grade0(self) -> None:
        # 12-bit packed RGB: 4 bits per component (R,G,B).
        # Encoded as 0x00F (R=15,G=0,B=0), stored little-endian => 0F 00.
        ut = UnitType(
            id=2,
            model="rgb-test",
            manufacturer="test",
            mode="",
            stateLength=2,
            controls=[
                UnitControl(
                    type=UnitControlType.RGB,
                    offset=0,
                    length=12,
                    default=0,
                    readonly=False,
                ),
            ],
        )

        u = Unit(
            _typeId=ut.id,
            deviceId=21,
            uuid="dummy",
            address="00:00:00:00:00:00",
            name="dummy",
            firmwareVersion="0",
            unitType=ut,
            networkProtocolVersion=5,
            networkGrade=0,
        )
        u.setStateFromBytes(bytes.fromhex("0f00"))

        assert u.state is not None
        self.assertEqual(u.state.rgb, (255, 0, 0))


if __name__ == "__main__":
    unittest.main()
