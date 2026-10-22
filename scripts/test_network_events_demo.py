"""WebSocket delivery and reconnect regression tests for the local demo."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any

from aiohttp.test_utils import TestClient, TestServer
from network_events_demo import (
    EventBuffer,
    ReceiveDiagnostics,
    make_app,
    select_gateway,
)


class GatewaySelectionTest(unittest.TestCase):
    """Match actual BLE targets to one advertised network and unit identity."""

    def setUp(self) -> None:
        """Use synthetic public advertisement identities, with no credential source."""
        self.network = b"netone"
        self.anchor = self.advertisement("network", self.network + b"\x0b")

    @staticmethod
    def advertisement(address: str, payload: bytes) -> tuple[Any, Any]:
        """Represent one scanner result without advertising service UUIDs."""
        return SimpleNamespace(address=address), SimpleNamespace(
            manufacturer_data={963: payload}
        )

    def node(
        self,
        address: str,
        *,
        network: bytes | None = None,
        unit: int = 2,
        protocol: int = 11,
    ) -> tuple[Any, Any]:
        """Build the official 23-byte node advertisement layout."""
        return self.advertisement(
            address,
            bytes(12)
            + (self.network if network is None else network)
            + bytes([unit, protocol, 0, 0, 0]),
        )

    def test_selects_same_network_and_unit_without_service_uuid_filter(self) -> None:
        """Skip another network, another unit and a truncated node record."""
        target = self.node("target")
        truncated_device, truncated_adv = self.node("truncated")
        truncated_adv.manufacturer_data[963] = truncated_adv.manufacturer_data[963][:-1]
        scan = {
            "anchor": self.anchor,
            "foreign": self.node("foreign", network=b"nettwo"),
            "other": self.node("other", unit=3),
            "target": target,
            "truncated": (truncated_device, truncated_adv),
        }
        self.assertIs(select_gateway(scan, "NETWORK", 2), target[0])

    def test_missing_and_ambiguous_targets_fail_instead_of_changing_gateway(
        self,
    ) -> None:
        """Do not silently choose a different node or one of two matching nodes."""
        with self.assertRaisesRegex(ConnectionError, "found 0"):
            select_gateway(
                {"anchor": self.anchor, "other": self.node("other", unit=3)},
                "network",
                2,
            )
        with self.assertRaisesRegex(ConnectionError, "found 2"):
            select_gateway(
                {
                    "anchor": self.anchor,
                    "one": self.node("one"),
                    "two": self.node("two"),
                },
                "network",
                2,
            )

    def test_network_reference_and_evo_protocol_are_required(self) -> None:
        """Reject an invalid network advertisement and an unsupported node protocol."""
        with self.assertRaisesRegex(ConnectionError, "network advertisement"):
            select_gateway(
                {"anchor": self.advertisement("network", bytes(6))}, "network", 2
            )
        with self.assertRaisesRegex(ValueError, "EVO"):
            select_gateway(
                {"anchor": self.anchor, "target": self.node("target", protocol=9)},
                "network",
                2,
            )


class DemoStreamTest(unittest.IsolatedAsyncioTestCase):
    """Exercise the actual HTTP/WebSocket application without a Bluetooth device."""

    async def asyncSetUp(self) -> None:
        """Start a fresh, credential-free app for each behavior."""
        self.buffer = EventBuffer(capacity=3)
        self.client = TestClient(TestServer(make_app(self.buffer)))
        await self.client.start_server()

    async def asyncTearDown(self) -> None:
        """Close clients and the HTTP listener."""
        await self.client.close()

    async def test_push_and_reconnect_only_delivers_unseen_rows(self) -> None:
        """New rows push immediately; reconnect resumes after the supplied cursor."""
        ws = await self.client.ws_connect("/ws")
        initial = await ws.receive_json(timeout=1)
        self.assertTrue(initial["reset"])
        self.buffer.append({"type": "input", "unit": 23, "value": "button_press"})
        pushed = await ws.receive_json(timeout=0.5)
        self.assertEqual([row["id"] for row in pushed["events"]], [1])
        self.assertEqual(pushed["events"][0]["value"], "button_press")
        self.buffer.set_status(state="connected", message="Ready")
        status = await ws.receive_json(timeout=0.5)
        self.assertEqual(status["events"], [])
        self.assertEqual(status["status"]["state"], "connected")
        await ws.close()
        self.buffer.append({"type": "input", "unit": 23, "value": "button_release"})
        ws = await self.client.ws_connect(f"/ws?after=1&session={initial['session']}")
        replay = await ws.receive_json(timeout=1)
        self.assertFalse(replay["reset"])
        self.assertEqual([row["id"] for row in replay["events"]], [2])
        await ws.close()

    async def test_retention_gap_and_server_session_reset(self) -> None:
        """Report a lost retention window and reset a cursor from an old process."""
        for number in range(6):
            self.buffer.append({"type": "input", "value": number})
        ws = await self.client.ws_connect(f"/ws?after=1&session={self.buffer.session}")
        replay = await ws.receive_json(timeout=1)
        self.assertEqual([row["id"] for row in replay["events"]], [4, 5, 6])
        self.assertEqual((replay["missed"], replay["expired"]), (2, 3))
        await ws.close()
        ws = await self.client.ws_connect("/ws?after=99&session=old-session")
        reset = await ws.receive_json(timeout=1)
        self.assertTrue(reset["reset"])
        self.assertEqual(len(reset["events"]), 3)
        await ws.close()

    async def test_export_matches_retained_history_and_invalid_cursor_fails(
        self,
    ) -> None:
        """Export remains usable independently of the active WebSocket."""
        self.buffer.append({"type": "presence", "value": "1"})
        response = await self.client.get("/export.json")
        self.assertEqual((await response.json())[0]["type"], "presence")
        self.assertIn("attachment", response.headers["Content-Disposition"])
        response = await self.client.get("/api/events?after=-1")
        self.assertEqual(response.status, 400)

    async def test_history_survives_restart_and_exports_beyond_live_window(
        self,
    ) -> None:
        """Restart retains session and IDs, and export contains the full history."""
        with TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            buffer = EventBuffer(capacity=2, history_path=path)
            for number in range(5):
                buffer.append({"type": "input", "value": number})
            restarted = EventBuffer(capacity=2, history_path=path)
            self.assertEqual(restarted.session, buffer.session)
            self.assertEqual(restarted.sequence, 5)
            self.assertEqual([row["id"] for row in restarted.rows], [4, 5])
            self.assertEqual([row["id"] for row in restarted.export()], [1, 2, 3, 4, 5])
            restarted.append({"type": "input", "value": "next"})
            self.assertEqual(restarted.rows[-1]["id"], 6)

    async def test_receive_metadata_is_persisted_and_pushed_without_payloads(
        self,
    ) -> None:
        """Expose receive and suppression counts independently of event rows."""
        with TemporaryDirectory() as directory:
            path = Path(directory) / "receive.jsonl"
            diagnostics = ReceiveDiagnostics(self.buffer, path)
            ws = await self.client.ws_connect("/ws")
            await ws.receive_json(timeout=1)
            for sequence in (8, 10):
                diagnostics.record(
                    {
                        "stage": "evo_receive",
                        "arrival_sequence": sequence,
                        "packet_sequence": sequence,
                        "wire_length": 33,
                        "verified": True,
                        "packet_type": 7,
                    }
                )
            diagnostics.record(
                {
                    "stage": "switch_decode",
                    "arrival_sequence": 10,
                    "packet_sequence": 10,
                    "frames": 2,
                    "button_frames": 2,
                    "input_frames": 0,
                    "ignored_frames": 0,
                    "legacy_emitted": 1,
                    "suppressed_copies": 1,
                    "suppressed_paired": 0,
                }
            )
            pushed = await ws.receive_json(timeout=1)
            rx = pushed["status"]["receive"]
            self.assertEqual((rx["packets"], rx["type7_packets"]), (2, 2))
            self.assertEqual((rx["legacy_emitted"], rx["legacy_copies"]), (1, 1))
            self.assertEqual(pushed["events"], [])
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(records[1]["sequence_delta"], 2)
            self.assertEqual(records[-1]["suppressed_copies"], 1)
            await ws.close()


if __name__ == "__main__":
    unittest.main()
