"""Observable network-event behavior from the Android 3.21.0 profile contract."""

import asyncio
import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock, patch

from bleak.backends.characteristic import BleakGATTCharacteristic
from cryptography.exceptions import InvalidSignature

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from CasambiBt import Casambi, NetworkEventDecoder, Unit  # noqa: E402
from CasambiBt._client import (  # noqa: E402
    CasambiClient,
    ConnectionState,
    IncommingPacketType,
    ProtocolMode,
)
from CasambiBt._network import Network  # noqa: E402


def control(kind: str, offset: int, length: int, **kwargs: Any) -> dict[str, Any]:
    """Describe a public fixture control."""
    return {"type": kind, "offset": offset, "length": length, **kwargs}


def unit(controls: list[dict[str, Any]], unit_id: int = 4) -> Unit:
    """Build a synthetic device with no network credentials."""
    return cast(
        Unit,
        SimpleNamespace(
            deviceId=unit_id,
            name=f"Device {unit_id}",
            unitType=SimpleNamespace(id=42, eventProfile={"controls": controls}),
        ),
    )


def invocation(
    opcode: int,
    target: int,
    payload: bytes,
    *,
    flags: int = 0x0800,
    origin: int = 0x0201,
    age: int = 0,
    handle: int | None = None,
) -> bytes:
    """Build one official INVOCATION frame with an optional response handle."""
    flags |= len(payload)
    if handle is not None:
        flags |= 0x0200
    header = (
        flags.to_bytes(2, "big")
        + bytes([opcode])
        + origin.to_bytes(2, "big")
        + target.to_bytes(2, "big")
        + age.to_bytes(2, "big")
    )
    return header + (bytes([handle]) if handle is not None else b"") + payload


class NetworkEventsTest(unittest.TestCase):
    """Control extraction, conversion, suppression and public callback delivery."""

    def test_input_display_keeps_switch_unit_and_original_four_button_number(
        self,
    ) -> None:
        """Keep the forwarding node distinct from the switch and its input label."""
        for index, label in ((0, 4), (1, 1), (2, 2), (3, 3), (4, None), (7, None)):
            row = NetworkEventDecoder.decode_invocations(
                invocation(29 + index, 0x1E06, b"\x80\x00\x00", origin=0x0201),
                names={30: "Entry"},
            )[0]
            self.assertEqual((row["unit_id"], row["origin_unit_id"]), (30, 2))
            self.assertEqual((row["button_index"], row["button"]), (index, label))
            self.assertEqual(row["input_action"], "press")

    def test_receive_metadata_fanout_survives_consumer_failure_without_logging_values(
        self,
    ) -> None:
        """One diagnostic consumer cannot stop another or leak its exception value."""
        casa = Casambi()
        failed = Mock(side_effect=ValueError("synthetic-private-marker"))
        received = Mock()
        casa.registerReceiveDiagnosticHandler(failed)
        casa.registerReceiveDiagnosticHandler(received)
        with self.assertLogs("CasambiBt._casambi", level="ERROR") as captured:
            casa._receiveDiagnosticCallback({"stage": "evo_receive", "verified": True})
        received.assert_called_once_with({"stage": "evo_receive", "verified": True})
        self.assertNotIn("synthetic-private-marker", "\n".join(captured.output))
        casa.unregisterReceiveDiagnosticHandler(failed)
        casa.unregisterReceiveDiagnosticHandler(received)

    def test_connection_info_reports_authenticated_observed_node_only(self) -> None:
        """Expose the actual GATT identity without carrying network configuration."""
        casa = Casambi()
        self.assertIsNone(casa.connectionInfo)
        casa._casaClient = cast(
            CasambiClient,
            SimpleNamespace(
                _connectionState=ConnectionState.AUTHENTICATED,
                address="AA:BB:CC:DD:EE:02",
                _unit=2,
                _deviceProtocolVersion=43,
                protocolMode=ProtocolMode.EVO,
            ),
        )
        self.assertEqual(
            casa.connectionInfo,
            {
                "address": "AA:BB:CC:DD:EE:02",
                "gateway_unit": 2,
                "device_protocol": 43,
                "protocol_mode": "evo",
            },
        )

    def test_mixed_unaligned_fields_and_unchanged_state(self) -> None:
        """Report changed presence and lux independently at their bit offsets."""
        device = unit([control("presence", 3, 1), control("lux", 9, 16)])
        decoder = NetworkEventDecoder()
        state = ((1 << 3) | (412 << 9)).to_bytes(4, "little")
        now = datetime(2026, 10, 22, tzinfo=UTC)
        rows = decoder.decode(device, state, timestamp=now)
        self.assertEqual(
            [(r["type"], r["value"]) for r in rows],
            [("presence", "1"), ("lux", "412 lux")],
        )
        self.assertEqual(rows[0]["time"], int(now.timestamp() * 1000))
        self.assertEqual(rows[1]["offset"], 9)
        self.assertEqual(decoder.decode(device, state), [])
        changed = ((1 << 3) | (413 << 9)).to_bytes(4, "little")
        self.assertEqual([r["type"] for r in decoder.decode(device, changed)], ["lux"])
        decoder.reset()
        self.assertEqual(len(decoder.decode(device, changed)), 2)

    def test_dedup_is_per_unit_and_control(self) -> None:
        """Equal values on different fields or devices are distinct observations."""
        controls = [control("button", 0, 1), control("button", 1, 1)]
        decoder = NetworkEventDecoder()
        self.assertEqual(len(decoder.decode(unit(controls, 1), b"\x00")), 2)
        self.assertEqual(len(decoder.decode(unit(controls, 2), b"\x00")), 2)
        changed = decoder.decode(unit(controls, 1), b"\x02")
        self.assertEqual(
            [(r["control_index"], r["value"]) for r in changed], [(1, "1")]
        )

    def test_partial_state_does_not_invent_unreceived_values(self) -> None:
        """Wait for field bytes before emitting a first observation."""
        device = unit([control("dimmer", 0, 8), control("lux", 8, 16)])
        decoder = NetworkEventDecoder()
        self.assertEqual(
            [r["type"] for r in decoder.decode(device, b"\xff")], ["dimmer"]
        )
        self.assertEqual(decoder.decode(device, b"\xff"), [])
        rows = decoder.decode(device, b"\xff\x00\x00")
        self.assertEqual([(r["type"], r["value"]) for r in rows], [("lux", "0 lux")])

    def test_field_across_64_bit_boundary_and_zero(self) -> None:
        """Extract fields crossing a machine-word boundary without losing zero."""
        device = unit([control("lux", 61, 16)])
        decoder = NetworkEventDecoder()
        for value in (0, 1, 65535, 0):
            rows = decoder.decode(device, (value << 61).to_bytes(10, "little"))
            self.assertEqual(rows[0]["numeric_value"], value)

    def test_percent_temperature_and_xy_boundaries(self) -> None:
        """Convert minimum, middle and maximum fixture values for display."""
        for raw, expected in ((0, "0.0 %"), (128, "50.2 %"), (255, "100.0 %")):
            rows = NetworkEventDecoder().decode(
                unit([control("dimmer", 0, 8)]), bytes([raw])
            )
            self.assertEqual(rows[0]["value"], expected)
        for raw, expected in ((0, "2000 K"), (128, "4259 K"), (255, "6500 K")):
            rows = NetworkEventDecoder().decode(
                unit([control("temperature", 0, 8, min=2000, max=6500)]), bytes([raw])
            )
            self.assertEqual(rows[0]["value"], expected)
        row = NetworkEventDecoder().decode(unit([control("xy", 0, 16)]), b"\x00\xff")[0]
        self.assertEqual(row["value"], "X:1.000, Y:0.000")

    def test_sensor_scaled_offset_and_format(self) -> None:
        """Respect sensor offsets, scaled ranges, units and display formats."""
        cases = [
            (control("sensor", 0, 8, min=-40, max=100, unit="°C"), 50, 10, "10 °C"),
            (
                control("sensor", 0, 8, min=-40, max=100, valueType=1, unit="°C{.1}"),
                255,
                100,
                "100.0 °C",
            ),
            (
                control("sensor", 0, 8, min=0, max=255, unit="V{.2,*0.1}"),
                12,
                12,
                "1.20 V",
            ),
            (control("sensor", 0, 8, min=0, max=255, unit="hex"), 15, 15, "0x0F"),
            (
                control("sensor", 0, 8, min=0, max=255, unit="|Open|Motion|Fault"),
                5,
                5,
                "Open, Fault",
            ),
        ]
        for field, raw, value, display in cases:
            with self.subTest(field=field):
                row = NetworkEventDecoder().decode(unit([field]), bytes([raw]))[0]
                self.assertEqual((row["numeric_value"], row["value"]), (value, display))

    def test_fixture_string_formats_and_hidden_kelvins(self) -> None:
        """Respect fixture format/unit overrides and the official CCT display mode."""
        device = unit([control("sensor", 0, 8, name="$voltage", min=0, max=255)])
        profile = device.unitType.eventProfile
        assert profile is not None
        profile["strings"] = {"$voltage": {"unit": "V", "format": "{.2,*0.1}"}}
        self.assertEqual(
            NetworkEventDecoder().decode(device, b"\x0c")[0]["value"], "1.20 V"
        )
        device = unit([control("temperature", 0, 8, min=2000, max=6500)])
        profile = device.unitType.eventProfile
        assert profile is not None
        profile["strings"] = {"$control_temperature": {"style": "hidden-kelvins"}}
        self.assertEqual(
            NetworkEventDecoder().decode(device, b"\x80")[0]["value"], "50 %"
        )

    def test_multiplexed_sensor_uses_selected_descriptor(self) -> None:
        """Interpret multiplexed values using the selected sensor metadata."""
        controls = [
            control("sensorgroup", 0, 8),
            control("sensor", 8, 0, min=-40, max=100, tag=3, unit="°C"),
            control("sensor", 8, 0, min=0, max=1000, tag=4, unit="ppm"),
            control("sensorgroupvalue", 8, 16),
        ]
        decoder = NetworkEventDecoder()
        row = decoder.decode(unit(controls), b"\x01\x32\x00")[0]
        self.assertEqual(
            (row["type"], row["sensor_tag"], row["value"]), ("sensor", 3, "10 °C")
        )
        row = decoder.decode(unit(controls), b"\x02\x64\x00")[0]
        self.assertEqual((row["sensor_tag"], row["value"]), (4, "100 ppm"))
        self.assertEqual(decoder.decode(unit(controls), b"\x00\x00\x00"), [])

    def test_invalid_profile_fails_with_context(self) -> None:
        """Reject malformed layouts and unsupported sensor encodings."""
        with self.assertRaisesRegex(ValueError, "Invalid fixture control layout"):
            NetworkEventDecoder().decode(unit([control("lux", -1, 8)]), b"\x00")
        with self.assertRaisesRegex(ValueError, "valueType"):
            NetworkEventDecoder().decode(
                unit([control("sensor", 0, 8, valueType=9)]), b"\x00"
            )

    def test_public_callbacks_receive_state_and_input_and_unregister(self) -> None:
        """Deliver both event sources while preserving the existing switch callback."""
        casa = Casambi()
        device = unit([control("presence", 0, 1)])
        self.enterContext(
            patch.object(device, "setStateFromBytes", new=Mock(), create=True)
        )
        casa._casaNetwork = cast(
            Network, SimpleNamespace(units=[device], _networkRevision=1)
        )
        rows: list[dict[str, Any]] = []
        switch_rows: list[dict[str, Any]] = []
        casa.registerNetworkEventHandler(rows.append)
        casa.registerSwitchEventHandler(switch_rows.append)
        state = {"id": 4, "state": b"\x01", "on": True, "online": True}
        casa._dataCallback(IncommingPacketType.UnitState, state)
        casa._dataCallback(IncommingPacketType.UnitState, state)
        event = {
            "unit_id": 4,
            "event": "button_press",
            "button": 1,
            "payload_hex": b"0100",
        }
        client = CasambiClient(
            "synthetic",
            casa._dataCallback,
            lambda: None,
            Mock(),
            invocationCallback=casa._invocationCallback,
        )
        client._parseSwitchEvent(invocation(30, 0x0406, b"\x89\x00\x02"), 8)
        self.assertEqual([r["type"] for r in rows], ["presence", "input"])
        self.assertEqual(rows[1]["interpreted_payload_hex"], "890002")
        self.assertEqual(rows[1]["source_stream"], "button_event")
        self.assertEqual([row["event"] for row in switch_rows], [event["event"]])
        casa.unregisterNetworkEventHandler(rows.append)
        casa._dataCallback(IncommingPacketType.UnitState, {**state, "state": b"\x00"})
        self.assertEqual(len(rows), 2)

    def test_invocation_header_flags_and_input_value_endianness(self) -> None:
        """Keep origin, target, optional handle and packed input fields distinct."""
        payload = invocation(
            66,
            0x2012,
            b"\x09\xf9\x34\x12",
            flags=0x7DC0,
            origin=0x0207,
            age=0x1234,
            handle=0x56,
        )
        row = NetworkEventDecoder.decode_invocations(
            payload, names={32: "Switch"}, packet_sequence=4, arrival_sequence=8
        )[0]
        self.assertEqual(
            (row["unit"], row["origin_unit_id"], row["origin_counter"]), (32, 2, 7)
        )
        self.assertEqual(
            (row["origin_handle"], row["lifetime"], row["age"]), (0x56, 15, 0x1234)
        )
        self.assertTrue(
            row["respond"] and row["unique"] and row["session"] and row["flag_0400"]
        )
        self.assertEqual(
            (row["input_index"], row["input_channel"], row["input_value16"]),
            (2, 1, 0x1234),
        )
        self.assertEqual((row["packet_sequence"], row["arrival_sequence"]), (4, 8))
        self.assertEqual(row["opcode_name"], "FunctionNotifyInput2")

    def test_receive_diagnostics_distinguish_verification_and_legacy_suppression(
        self,
    ) -> None:
        """Keep received copies visible and identify where legacy events stop."""
        raw: list[tuple] = []
        semantic: list[dict[str, Any]] = []
        diagnostics: list[dict[str, Any]] = []
        client = CasambiClient(
            "synthetic",
            lambda _kind, event: semantic.append(event),
            lambda: None,
            Mock(),
            invocationCallback=lambda *args: raw.append(args),
            receiveDiagnosticCallback=diagnostics.append,
        )
        client._nonce = bytes(16)
        client._encryptor = Mock()
        payload = invocation(30, 0x1F06, b"\x89\x00\x02", origin=0x1FB1)
        client._encryptor.decryptAndVerify.return_value = b"\x07" + payload
        handle = cast(BleakGATTCharacteristic, SimpleNamespace(uuid="synthetic"))
        for sequence in (8, 9):
            client._establishedNofityCallback(
                handle, sequence.to_bytes(4, "little") + bytes(16)
            )
        self.assertEqual(len(raw), 2)
        self.assertEqual([e["event"] for e in semantic], ["button_press"])
        self.assertEqual(
            [r["stage"] for r in diagnostics],
            [
                "evo_receive",
                "switch_decode",
                "evo_receive",
                "switch_decode",
            ],
        )
        self.assertEqual(diagnostics[-1]["suppressed_copies"], 1)
        self.assertEqual(diagnostics[-1]["legacy_emitted"], 0)
        self.assertEqual(diagnostics[-2]["packet_sequence"], 9)
        self.assertTrue(diagnostics[-2]["verified"])
        client._encryptor.decryptAndVerify.side_effect = InvalidSignature
        with self.assertLogs(client._logger, level="ERROR"):
            client._establishedNofityCallback(handle, bytes(20))
        self.assertFalse(diagnostics[-1]["verified"])
        self.assertIsNone(diagnostics[-1]["packet_type"])
        self.assertEqual(len(raw), 2)

    def test_button_payload_partitions_and_raw_index(self) -> None:
        """Match the official three-byte minimum and expose all index/P/S bits."""
        for payload in (b"", b"\x80", b"\x80\x00"):
            row = NetworkEventDecoder.decode_invocations(
                invocation(29, 0x2006, payload), names={}
            )[0]
            self.assertEqual(row["type"], "malformed_invocation")
        row = NetworkEventDecoder.decode_invocations(
            invocation(36, 0x2006, b"\xff\x00\x01"), names={}
        )[0]
        self.assertEqual(
            (row["button_event_index"], row["pressed"], row["param_p"], row["param_s"]),
            (7, True, 15, 7),
        )
        self.assertEqual(row["source_stream"], "button_event")

    def test_raw_invocations_do_not_pair_away_complementary_packet_loss(self) -> None:
        """Retain the second release when alternate source reports are missing."""
        decoder = NetworkEventDecoder()
        frames = [
            invocation(30, 0x2006, b"\x89\x00\x02", origin=0x20A1),
            invocation(30, 0x2006, b"\x09\x00\x0e", origin=0x20A6),
            invocation(30, 0x2006, b"\x89\x00\x02", origin=0x20B1),
            invocation(65, 0x2012, b"\x02\x09", origin=0x02B2),
        ]
        rows = [
            row
            for frame in frames
            for row in decoder.decode_invocations(frame, names={})
        ]
        self.assertEqual(len(rows), 4)
        self.assertEqual(
            (rows[-1]["source_stream"], rows[-1]["input_code"]), ("notify_input", 2)
        )
        self.assertEqual(len(decoder.decode_invocations(frames[0], names={})), 1)

    def test_unknown_payload_stays_opaque_and_truncated_stream_is_visible(self) -> None:
        """Expose unknown headers and explicit truncation without dumping payloads."""
        data = invocation(26, 0x2001, b"opaque-test-data") + b"\x08"
        rows = NetworkEventDecoder.decode_invocations(data, names={})
        self.assertEqual(
            [row["type"] for row in rows], ["invocation", "malformed_invocation"]
        )
        self.assertEqual(rows[0]["opcode_name"], "FunctionSetParameter")
        self.assertEqual(rows[0]["payload_length"], len(b"opaque-test-data"))
        self.assertNotIn(b"opaque-test-data".hex(), str(rows))
        self.assertNotIn("opaque-test-data", str(rows))
        short_input = NetworkEventDecoder.decode_invocations(
            invocation(64, 0x2012, b"\x01\x08"), names={}
        )[0]
        self.assertIsNone(short_input["input_value16"])


class ReceiveQueueTest(unittest.IsolatedAsyncioTestCase):
    """Preserve a failed receive's cause while continuing the queue."""

    async def test_callback_failure_is_counted_and_later_packet_is_processed(
        self,
    ) -> None:
        """Publish only the exception class at the queue's recovery boundary."""
        diagnostics: list[dict[str, Any]] = []
        client = CasambiClient(
            "synthetic",
            Mock(),
            lambda: None,
            Mock(),
            receiveDiagnosticCallback=diagnostics.append,
        )
        client._callbackQueue = asyncio.Queue()
        multiplexer = Mock(side_effect=[ValueError("opaque-test-data"), None])
        self.enterContext(patch.object(client, "_callbackMulitplexer", new=multiplexer))
        for _ in range(2):
            client._queueCallback(
                cast(BleakGATTCharacteristic, SimpleNamespace(uuid="synthetic")),
                bytes(20),
            )
        with self.assertLogs(client._logger, level="WARNING"):
            task = asyncio.create_task(client._processCallbacks())
            try:
                await asyncio.wait_for(client._callbackQueue.join(), timeout=1)
            finally:
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
        self.assertEqual(multiplexer.call_count, 2)
        self.assertEqual(
            diagnostics,
            [
                {
                    "stage": "callback_error",
                    "arrival_sequence": 0,
                    "exception_type": "ValueError",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
