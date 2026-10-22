from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from bleak import BleakClient
from cryptography.hazmat.primitives.asymmetric import ec

# Allow tests to run without installing the package.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from CasambiBt._client import (  # noqa: E402
    CasambiClient,
    ConnectionState,
    IncommingPacketType,
)
from CasambiBt.errors import ProtocolError  # noqa: E402
from CasambiBt._network import Network  # noqa: E402


class _DummyNetwork:
    # Cloud protocol version can be "legacy" even when the connected device speaks EVO.
    protocolVersion = 5

    def classicVisitorKey(self) -> bytes | None:  # noqa: D401
        return None

    def classicManagerKey(self) -> bytes | None:  # noqa: D401
        return None

    def hasClassicKeys(self) -> bool:  # noqa: D401
        return False


class _StubGattClient:
    def __init__(self, resp: bytes) -> None:
        self._resp = resp

    async def read_gatt_char(self, _uuid: str) -> bytes:
        return self._resp

    async def start_notify(self, *_args, **_kwargs) -> None:
        raise AssertionError(
            "start_notify should not be called for short/invalid NodeInfo"
        )


class _DisconnectingGattClient:
    is_connected = False

    def __init__(self, client: CasambiClient) -> None:
        self._client = client

    async def read_gatt_char(self, _uuid: str) -> bytes:
        return b"\x01\x2b\x9e\x00\x18\x00\xf0" + (b"\x01" * 16)

    async def start_notify(self, *_args, **_kwargs) -> None:
        self._client._on_disconnect(self)  # noqa: SLF001


class TestLegacyProtocolHandling(unittest.TestCase):
    def test_checkProtocolVersion_legacy_warns_by_default(self) -> None:
        def cb(_: IncommingPacketType, __: dict) -> None:
            return

        c = CasambiClient("00:00:00:00:00:00", cb, lambda: None, _DummyNetwork())
        # Should not raise (we want tester logs and best-effort support).
        c._checkProtocolVersion(5, source="cloud_protocol")


class TestExchangeKeyNodeInfoGuards(unittest.IsolatedAsyncioTestCase):
    async def test_network_key_exchange_matches_official_public_key_and_trailer(
        self,
    ) -> None:
        """Send the official network handshake and reach the authentication stage."""
        network = SimpleNamespace(
            protocolVersion=11, keyStore=SimpleNamespace(getKey=lambda: True)
        )
        client = CasambiClient("synthetic", lambda *_args: None, lambda: None, cast(Network, network))
        client._connectionState = ConnectionState.CONNECTED
        public_key = ec.derive_private_key(123456789, ec.SECP256R1()).public_key()
        written: list[bytes] = []

        class Gatt:
            async def read_gatt_char(self, _uuid: str) -> bytes:
                return b"\x01\x0b\x9e\x00\x18\x00\xf0" + bytes(16)

            async def start_notify(self, *_args: Any, **_kwargs: Any) -> None:
                client._pubKey = public_key
                client._transportKey = bytearray(range(16))
                client._notifySignal.set()

            async def write_gatt_char(self, _uuid: str, packet: bytes) -> None:
                written.append(packet)
                client._notifySignal.set()

        client._gattClient = cast(BleakClient, Gatt())
        await client.exchangeKey()
        numbers = public_key.public_numbers()
        self.assertEqual(
            written,
            [
                b"\x02"
                + numbers.x.to_bytes(32, "little")
                + numbers.y.to_bytes(32, "little")
                + b"\x0d\x01",
            ],
        )
        self.assertEqual(client._connectionState, ConnectionState.KEY_EXCHANGED)

    async def test_exchangeKey_short_nodeinfo_raises_protocol_error(self) -> None:
        def cb(_: IncommingPacketType, __: dict) -> None:
            return

        c = CasambiClient("00:00:00:00:00:00", cb, lambda: None, _DummyNetwork())
        c._connectionState = ConnectionState.CONNECTED
        c._gattClient = _StubGattClient(b"\x01\x0b")  # NodeInfo prefix but too short

        with self.assertRaises(ProtocolError):
            await c.exchangeKey()

    async def test_exchangeKey_disconnect_while_waiting_for_notify_raises(self) -> None:
        def cb(_: IncommingPacketType, __: dict) -> None:
            return

        c = CasambiClient("00:00:00:00:00:00", cb, lambda: None, _DummyNetwork())
        c._connectionState = ConnectionState.CONNECTED
        c._gattClient = _DisconnectingGattClient(c)

        with self.assertRaises(ProtocolError):
            await c.exchangeKey()
