from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Allow tests to run without installing the package.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from CasambiBt._classic_crypto import classic_cmac, classic_cmac_prefix  # noqa: E402
from CasambiBt._client import CasambiClient, IncommingPacketType  # noqa: E402


class _DummyNetwork:
    protocolVersion = 10

    def classicVisitorKey(self) -> bytes | None:  # noqa: D401
        return None

    def classicManagerKey(self) -> bytes | None:  # noqa: D401
        return None

    def hasClassicKeys(self) -> bool:  # noqa: D401
        return False


class TestClassicProtocolHelpers(unittest.TestCase):
    def test_classic_cmac_matches_rfc4493_vectors(self) -> None:
        # RFC 4493 test vectors (AES-CMAC).
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

        # Example 2 (16 bytes)
        msg16 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        exp16 = bytes.fromhex("070a16b46b4d4144f79bdd9dd04a287c")

        # Example 3 (32 bytes)
        msg32 = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
        )
        exp32 = bytes.fromhex("ce0cbf1738f4df6428b1d93bf12081c9")

        # Example 4 (48 bytes)
        msg48 = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
        )
        exp48 = bytes.fromhex("c47c4d9d64588f67fb9de6fe745d7fbf")

        for msg, expected in ((msg16, exp16), (msg32, exp32), (msg48, exp48)):
            conn_hash8 = msg[:8]
            payload = msg[8:]
            mac = classic_cmac(key, conn_hash8, payload)
            self.assertEqual(mac, expected)
            self.assertEqual(classic_cmac_prefix(key, conn_hash8, payload, 4), expected[:4])
            self.assertEqual(classic_cmac_prefix(key, conn_hash8, payload, 16), expected)

    def test_classic_command_encoding_matches_android_layout(self) -> None:
        # Ground truth: casambi-android `u1.C1753e.a(P)`:
        # [len+239][ordinal|flags][div][target?][lifetime=200][payload...]
        parsed: list[dict] = []

        def cb(_: IncommingPacketType, data: dict) -> None:
            parsed.append(data)

        c = CasambiClient("00:00:00:00:00:00", cb, lambda: None, _DummyNetwork())

        # Unit level command: ordinal=7, div present, target present, lifetime=200, payload=0x54
        cmd = c.buildClassicCommand(7, bytes([0x54]), target_id=3, div=0x12, lifetime=200)
        self.assertEqual(cmd.hex(), "f5c71203c854")

        # All units level: ordinal=4, div present, no target, lifetime=200, payload=0xff
        cmd2 = c.buildClassicCommand(4, bytes([0xFF]), target_id=None, div=0x01, lifetime=200)
        self.assertEqual(cmd2.hex(), "f44401c8ff")

        # target_id=0 is treated as "no target" (Android only writes target when > 0).
        cmd3 = c.buildClassicCommand(4, bytes([0xFF]), target_id=0, div=0x01, lifetime=200)
        self.assertEqual(cmd3.hex(), "f44401c8ff")


if __name__ == "__main__":
    unittest.main()
