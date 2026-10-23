"""State observed by consumers while a BLE disconnect is being dispatched."""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import cast

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from CasambiBt import Casambi  # noqa: E402
from CasambiBt._client import CasambiClient, ConnectionState  # noqa: E402
from CasambiBt._network import Network  # noqa: E402


class TestDisconnectCallbackState(unittest.TestCase):
    def _connected_casa(self) -> tuple[Casambi, CasambiClient]:
        casa = Casambi()
        unit = SimpleNamespace(deviceId=7, _online=True)
        casa._casaNetwork = cast(
            Network, SimpleNamespace(_networkRevision=3, units=[unit])
        )
        client = CasambiClient(
            "AA:BB:CC:DD:EE:07",
            lambda *_args: None,
            casa._disconnectCallback,
            casa._casaNetwork,
        )
        client._connectionState = ConnectionState.AUTHENTICATED
        casa._casaClient = client
        return casa, client

    def test_callbacks_see_disconnected_state(self) -> None:
        """A consumer that reconnects from the callback must not see a live link."""
        casa, client = self._connected_casa()
        seen: list[tuple[str, bool]] = []
        casa.registerUnitChangedHandler(
            lambda u: seen.append((f"unit {u.deviceId} online={u._online}", casa.connected))
        )
        casa.registerDisconnectCallback(lambda: seen.append(("disconnect", casa.connected)))

        client._on_disconnect(cast(object, None))

        self.assertEqual(
            seen, [("unit 7 online=False", False), ("disconnect", False)]
        )
        self.assertEqual(client._connectionState, ConnectionState.NONE)

    def test_disconnect_before_authentication_does_not_notify(self) -> None:
        """A mid-handshake drop wakes waiters with ERROR and skips consumers."""
        casa, client = self._connected_casa()
        client._connectionState = ConnectionState.KEY_EXCHANGED
        calls: list[str] = []
        casa.registerDisconnectCallback(lambda: calls.append("disconnect"))

        client._on_disconnect(cast(object, None))

        self.assertEqual(calls, [])
        self.assertEqual(client._connectionState, ConnectionState.ERROR)
        self.assertTrue(client._notifySignal.is_set())


if __name__ == "__main__":
    unittest.main()
