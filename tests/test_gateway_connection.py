"""Keep network identity independent of the selected GATT peripheral."""

import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from bleak.backends.device import BLEDevice

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from CasambiBt import Casambi  # noqa: E402


class GatewayConnectionTest(unittest.IsolatedAsyncioTestCase):
    """Exercise the public connection API without Bluetooth or a credential store."""

    async def test_selected_gateway_uses_original_network_identity(self) -> None:
        """Load original network keys and send GATT traffic to the chosen node."""
        device = BLEDevice("AA:BB:CC:DD:EE:02", "Node", {})
        casa = Casambi(Mock())
        casa._cache = AsyncMock()
        network = Mock(load=AsyncMock(), logIn=AsyncMock(), update=AsyncMock())
        with (
            patch.object(
                casa, "_connectClient", new_callable=AsyncMock
            ) as connect_client,
            patch("CasambiBt._casambi.Network", return_value=network) as factory,
            patch("CasambiBt._casambi.CasambiClient") as client,
        ):
            await casa.connect(
                device, "synthetic-password", networkAddress="11:22:33:44:55:66"
            )
        factory.assert_called_once_with("112233445566", casa._httpClient, casa._cache)
        casa._cache.setUuid.assert_awaited_once_with("112233445566")
        self.assertIs(client.call_args.args[0], device)
        network.logIn.assert_awaited_once_with("synthetic-password", False)
        connect_client.assert_awaited_once()

    async def test_default_connection_preserves_network_address(self) -> None:
        """Existing BLEDevice and string callers keep their network identity."""
        for target in (BLEDevice("AA:BB:CC:DD:EE:01", "Network", {}), "AABBCCDDEE01"):
            with self.subTest(target=target):
                casa = Casambi(Mock())
                casa._cache = AsyncMock()
                network = Mock(load=AsyncMock(), logIn=AsyncMock(), update=AsyncMock())
                with (
                    patch.object(casa, "_connectClient", new_callable=AsyncMock),
                    patch(
                        "CasambiBt._casambi.Network", return_value=network
                    ) as factory,
                    patch("CasambiBt._casambi.CasambiClient") as client,
                ):
                    await casa.connect(target, "synthetic-password")
                self.assertEqual(factory.call_args.args[0], "aabbccddee01")
                self.assertEqual(
                    client.call_args.args[0],
                    target if isinstance(target, BLEDevice) else "AA:BB:CC:DD:EE:01",
                )
