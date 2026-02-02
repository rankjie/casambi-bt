from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Allow tests to run without installing the package.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from CasambiBt._classic_crypto import (  # noqa: E402
    classic_cmac,
    classic_cmac_prefix,
    verify_classic_cmac,
    RFC4493_TEST_KEY,
    RFC4493_VECTORS,
)
from CasambiBt._client import (  # noqa: E402
    CasambiClient,
    ConnectionState,
    IncommingPacketType,
    ProtocolMode,
)


class _DummyNetwork:
    protocolVersion = 10

    def classicVisitorKey(self) -> bytes | None:  # noqa: D401
        return None

    def classicManagerKey(self) -> bytes | None:  # noqa: D401
        return None

    def hasClassicKeys(self) -> bool:  # noqa: D401
        return False

    def isManager(self) -> bool:  # noqa: D401
        return False


class _DummyNetworkWithKeys:
    protocolVersion = 5  # Classic protocol version

    def __init__(self, visitor_key: bytes | None = None, manager_key: bytes | None = None) -> None:
        self._visitor = visitor_key
        self._manager = manager_key

    def classicVisitorKey(self) -> bytes | None:  # noqa: D401
        return self._visitor

    def classicManagerKey(self) -> bytes | None:  # noqa: D401
        return self._manager

    def hasClassicKeys(self) -> bool:  # noqa: D401
        return bool(self._visitor or self._manager)

    def isManager(self) -> bool:  # noqa: D401
        return self._manager is not None


class _StubGattClient:
    def __init__(self) -> None:
        self.writes: list[tuple[str, bytes, bool]] = []

    async def write_gatt_char(self, uuid: str, data: bytes, response: bool = False) -> None:
        self.writes.append((uuid, bytes(data), bool(response)))


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

    def test_rfc4493_vectors_from_module(self) -> None:
        """Test using the vectors exported from _classic_crypto module."""
        for msg, expected in RFC4493_VECTORS:
            conn_hash8 = msg[:8]
            payload = msg[8:]
            mac = classic_cmac(RFC4493_TEST_KEY, conn_hash8, payload)
            self.assertEqual(mac, expected)

    def test_verify_classic_cmac(self) -> None:
        """Test the verify_classic_cmac helper."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        msg = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        expected = bytes.fromhex("070a16b46b4d4144f79bdd9dd04a287c")

        conn_hash8 = msg[:8]
        payload = msg[8:]

        # Correct prefix should verify
        self.assertTrue(verify_classic_cmac(key, conn_hash8, payload, expected[:4]))
        self.assertTrue(verify_classic_cmac(key, conn_hash8, payload, expected[:16]))

        # Wrong prefix should not verify
        wrong_prefix = bytes.fromhex("00000000")
        self.assertFalse(verify_classic_cmac(key, conn_hash8, payload, wrong_prefix))

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


class TestClassicSimpleCommandFormat(unittest.TestCase):
    """Test the alternative simple command format from BLE captures."""

    def test_simple_command_format_all_units(self) -> None:
        """Test simple command format for all units."""
        def cb(_: IncommingPacketType, data: dict) -> None:
            pass

        c = CasambiClient("00:00:00:00:00:00", cb, lambda: None, _DummyNetwork())
        c._classicCmdDiv = 0x03  # Set known counter

        # All units (0xFF), level 128
        cmd = c.buildClassicCommandSimple(0xFF, 128)
        # Expected: [counter=4][unit_id=0xFF][param_len=1][dimmer=128]
        self.assertEqual(cmd.hex(), "04ff0180")

    def test_simple_command_format_single_unit(self) -> None:
        """Test simple command format for single unit."""
        def cb(_: IncommingPacketType, data: dict) -> None:
            pass

        c = CasambiClient("00:00:00:00:00:00", cb, lambda: None, _DummyNetwork())
        c._classicCmdDiv = 0x03

        # Unit 4, level 0
        cmd = c.buildClassicCommandSimple(4, 0)
        # Expected: [counter=4][unit_id=4][param_len=1][dimmer=0]
        self.assertEqual(cmd.hex(), "04040100")

    def test_simple_command_format_with_extra(self) -> None:
        """Test simple command format with extra parameter (temperature/vertical)."""
        def cb(_: IncommingPacketType, data: dict) -> None:
            pass

        c = CasambiClient("00:00:00:00:00:00", cb, lambda: None, _DummyNetwork())
        c._classicCmdDiv = 0x03

        # Unit 4, level 0, extra 0xB3 (temperature)
        cmd = c.buildClassicCommandSimple(4, 0, extra=0xB3)
        # Expected: [counter=4][unit_id=4][param_len=2][dimmer=0][extra=0xB3]
        self.assertEqual(cmd.hex(), "040402" "00b3")


class TestClassicSendWithoutKeys(unittest.IsolatedAsyncioTestCase):
    async def test_classic_send_conformant_without_keys_has_zero_sig_and_seq(self) -> None:
        sent: list[tuple[str, bytes, bool]] = []

        def cb(_: IncommingPacketType, __: dict) -> None:
            return

        c = CasambiClient("00:00:00:00:00:00", cb, lambda: None, _DummyNetwork())
        c._gattClient = _StubGattClient()
        c._connectionState = ConnectionState.AUTHENTICATED
        c._protocolMode = ProtocolMode.CLASSIC
        c._dataCharUuid = "dummy"
        c._classicConnHash8 = b"\x11" * 8
        c._classicHeaderMode = "conformant"
        c._classicTxSeq = 0

        cmd = c.buildClassicCommand(4, bytes([0xFF]), div=0x01, lifetime=200)
        await c.send(cmd)

        stub = c._gattClient
        assert isinstance(stub, _StubGattClient)
        self.assertEqual(len(stub.writes), 1)
        _uuid, pkt, response = stub.writes[0]
        self.assertTrue(response)

        # [auth=0x02][sig(4x00)][seq=0x0001][cmd...]
        self.assertEqual(pkt[0], 0x02)
        self.assertEqual(pkt[1:5], b"\x00" * 4)
        self.assertEqual(pkt[5:7], b"\x00\x01")
        self.assertEqual(pkt[7:], cmd)

    async def test_classic_send_legacy_without_keys_has_zero_sig(self) -> None:
        def cb(_: IncommingPacketType, __: dict) -> None:
            return

        c = CasambiClient("00:00:00:00:00:00", cb, lambda: None, _DummyNetwork())
        c._gattClient = _StubGattClient()
        c._connectionState = ConnectionState.AUTHENTICATED
        c._protocolMode = ProtocolMode.CLASSIC
        c._dataCharUuid = "dummy"
        c._classicConnHash8 = b"\x11" * 8
        c._classicHeaderMode = "legacy"

        cmd = c.buildClassicCommand(4, bytes([0xFF]), div=0x01, lifetime=200)
        await c.send(cmd)

        stub = c._gattClient
        assert isinstance(stub, _StubGattClient)
        self.assertEqual(len(stub.writes), 1)
        _uuid, pkt, response = stub.writes[0]
        self.assertTrue(response)

        # [sig(4x00)][cmd...]
        self.assertEqual(pkt[:4], b"\x00" * 4)
        self.assertEqual(pkt[4:], cmd)


class TestClassicSendWithKeys(unittest.IsolatedAsyncioTestCase):
    """Test Classic send with actual keys for CMAC signing."""

    async def test_classic_send_conformant_with_visitor_key(self) -> None:
        """Test conformant mode with visitor key produces signed packet."""
        visitor_key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

        def cb(_: IncommingPacketType, __: dict) -> None:
            return

        network = _DummyNetworkWithKeys(visitor_key=visitor_key)
        c = CasambiClient("00:00:00:00:00:00", cb, lambda: None, network)
        c._gattClient = _StubGattClient()
        c._connectionState = ConnectionState.AUTHENTICATED
        c._protocolMode = ProtocolMode.CLASSIC
        c._dataCharUuid = "dummy"
        c._classicConnHash8 = bytes.fromhex("1122334455667788")
        c._classicHeaderMode = "conformant"
        c._classicTxSeq = 0

        cmd = c.buildClassicCommand(4, bytes([0xFF]), div=0x01, lifetime=200)
        await c.send(cmd)

        stub = c._gattClient
        assert isinstance(stub, _StubGattClient)
        self.assertEqual(len(stub.writes), 1)
        _uuid, pkt, response = stub.writes[0]
        self.assertTrue(response)

        # [auth=0x02][sig(4 bytes, NOT zero)][seq=0x0001][cmd...]
        self.assertEqual(pkt[0], 0x02)
        # Signature should NOT be all zeros (it's computed with the key)
        self.assertNotEqual(pkt[1:5], b"\x00" * 4)
        self.assertEqual(pkt[5:7], b"\x00\x01")  # seq = 1
        self.assertEqual(pkt[7:], cmd)

        # Verify the CMAC is correct
        cmac_input = pkt[5:]  # seq + cmd
        expected_sig = classic_cmac_prefix(visitor_key, c._classicConnHash8, cmac_input, 4)
        self.assertEqual(pkt[1:5], expected_sig)

    async def test_classic_send_legacy_with_visitor_key(self) -> None:
        """Test legacy mode with visitor key produces signed packet."""
        visitor_key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

        def cb(_: IncommingPacketType, __: dict) -> None:
            return

        network = _DummyNetworkWithKeys(visitor_key=visitor_key)
        c = CasambiClient("00:00:00:00:00:00", cb, lambda: None, network)
        c._gattClient = _StubGattClient()
        c._connectionState = ConnectionState.AUTHENTICATED
        c._protocolMode = ProtocolMode.CLASSIC
        c._dataCharUuid = "dummy"
        c._classicConnHash8 = bytes.fromhex("1122334455667788")
        c._classicHeaderMode = "legacy"

        cmd = c.buildClassicCommand(4, bytes([0xFF]), div=0x01, lifetime=200)
        await c.send(cmd)

        stub = c._gattClient
        assert isinstance(stub, _StubGattClient)
        self.assertEqual(len(stub.writes), 1)
        _uuid, pkt, response = stub.writes[0]
        self.assertTrue(response)

        # [sig(4 bytes, NOT zero)][cmd...]
        self.assertNotEqual(pkt[:4], b"\x00" * 4)
        self.assertEqual(pkt[4:], cmd)

        # Verify the CMAC is correct
        expected_sig = classic_cmac_prefix(visitor_key, c._classicConnHash8, cmd, 4)
        self.assertEqual(pkt[:4], expected_sig)


class TestClassicDiagnosticHistory(unittest.IsolatedAsyncioTestCase):
    """Test that TX/RX packets are recorded in diagnostic history."""

    async def test_tx_history_recorded(self) -> None:
        """Test that TX packets are recorded in history."""
        def cb(_: IncommingPacketType, __: dict) -> None:
            return

        c = CasambiClient("00:00:00:00:00:00", cb, lambda: None, _DummyNetwork())
        c._gattClient = _StubGattClient()
        c._connectionState = ConnectionState.AUTHENTICATED
        c._protocolMode = ProtocolMode.CLASSIC
        c._dataCharUuid = "dummy"
        c._classicConnHash8 = b"\x11" * 8
        c._classicHeaderMode = "conformant"
        c._classicTxSeq = 0

        # Initially empty
        self.assertEqual(len(c._classicTxHistory), 0)

        # Send a command
        cmd = c.buildClassicCommand(4, bytes([0xFF]), div=0x01, lifetime=200)
        await c.send(cmd)

        # Should have one entry in history
        self.assertEqual(len(c._classicTxHistory), 1)
        entry = c._classicTxHistory[0]
        self.assertIn("timestamp", entry)
        self.assertIn("header_mode", entry)
        self.assertIn("post_sign_hex", entry)
        self.assertEqual(entry["result"], "ok")

    async def test_getClassicDiagnostics_returns_data(self) -> None:
        """Test that getClassicDiagnostics returns structured data."""
        def cb(_: IncommingPacketType, __: dict) -> None:
            return

        c = CasambiClient("00:00:00:00:00:00", cb, lambda: None, _DummyNetwork())
        c._gattClient = _StubGattClient()
        c._connectionState = ConnectionState.AUTHENTICATED
        c._protocolMode = ProtocolMode.CLASSIC
        c._dataCharUuid = "dummy"
        c._classicConnHash8 = b"\x11" * 8
        c._classicHeaderMode = "conformant"
        c._classicTxSeq = 0

        # Send a command
        cmd = c.buildClassicCommand(4, bytes([0xFF]), div=0x01, lifetime=200)
        await c.send(cmd)

        # Get diagnostics
        diag = c.getClassicDiagnostics()
        self.assertEqual(diag["protocol_mode"], "CLASSIC")
        self.assertEqual(diag["classic_header_mode"], "conformant")
        self.assertEqual(diag["classic_tx_count"], 1)
        self.assertIn("classic_tx_history", diag)
        self.assertIn("classic_rx_stats", diag)


if __name__ == "__main__":
    unittest.main()
