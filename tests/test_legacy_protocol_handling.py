from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

# Allow tests to run without installing the package.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from CasambiBt._client import CasambiClient, ConnectionState, IncommingPacketType  # noqa: E402
from CasambiBt.errors import ProtocolError, UnsupportedProtocolVersion  # noqa: E402


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
        raise AssertionError("start_notify should not be called for short/invalid NodeInfo")


class TestLegacyProtocolHandling(unittest.TestCase):
    def test_checkProtocolVersion_legacy_warns_by_default(self) -> None:
        def cb(_: IncommingPacketType, __: dict) -> None:
            return

        c = CasambiClient("00:00:00:00:00:00", cb, lambda: None, _DummyNetwork())
        old = dict(os.environ)
        try:
            os.environ.pop("CASAMBI_BT_STRICT_PROTOCOL_VERSION", None)
            # Should not raise by default (we want tester logs).
            c._checkProtocolVersion(5, source="cloud_protocol")
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_checkProtocolVersion_legacy_can_be_strict(self) -> None:
        def cb(_: IncommingPacketType, __: dict) -> None:
            return

        c = CasambiClient("00:00:00:00:00:00", cb, lambda: None, _DummyNetwork())
        old = dict(os.environ)
        try:
            os.environ["CASAMBI_BT_STRICT_PROTOCOL_VERSION"] = "1"
            with self.assertRaises(UnsupportedProtocolVersion):
                c._checkProtocolVersion(5, source="cloud_protocol")
        finally:
            os.environ.clear()
            os.environ.update(old)


class TestExchangeKeyNodeInfoGuards(unittest.IsolatedAsyncioTestCase):
    async def test_exchangeKey_short_nodeinfo_raises_protocol_error(self) -> None:
        def cb(_: IncommingPacketType, __: dict) -> None:
            return

        c = CasambiClient("00:00:00:00:00:00", cb, lambda: None, _DummyNetwork())
        c._connectionState = ConnectionState.CONNECTED
        c._gattClient = _StubGattClient(b"\x01\x0b")  # NodeInfo prefix but too short

        with self.assertRaises(ProtocolError):
            await c.exchangeKey()

