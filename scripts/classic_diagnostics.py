#!/usr/bin/env python3
"""Standalone Classic protocol diagnostic script.

This script connects to a Classic Casambi network and attempts control operations
while logging comprehensive diagnostics. Testers can run this outside Home Assistant
to capture actionable logs for debugging Classic protocol issues.

Usage:
    python classic_diagnostics.py <uuid> <password> [--output <logfile>]

Example:
    python classic_diagnostics.py CE42027B8FDE mypassword --output classic_diag.log

The script will:
1. Connect to the network via Bluetooth
2. Read the connection hash
3. Subscribe to notifications
4. Attempt to set level 0 on all units
5. Wait 5 seconds for state updates
6. Attempt to set level 255 on all units
7. Wait 5 seconds for state updates
8. Attempt alternate packet format if CASAMBI_BT_CLASSIC_FORMAT=simple is set
9. Disconnect and save diagnostic log
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

# Allow running from source tree without installation
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

try:
    from bleak import BleakClient, BleakScanner
    from bleak.backends.device import BLEDevice
except ImportError:
    print("ERROR: bleak is required. Install with: pip install bleak")
    sys.exit(1)

from CasambiBt._constants import (
    CASA_AUTH_CHAR_UUID,
    CASA_CLASSIC_HASH_CHAR_UUID,
    CASA_CLASSIC_DATA_CHAR_UUID,
    CASA_CLASSIC_CA53_CHAR_UUID,
    CASA_CLASSIC_CONFORMANT_CA51_CHAR_UUID,
    CASA_CLASSIC_CONFORMANT_CA53_CHAR_UUID,
    CASA_UUID,
    CASA_UUID_CLASSIC,
)
from CasambiBt._classic_crypto import classic_cmac_prefix


class ClassicDiagnostics:
    """Classic protocol diagnostic runner."""

    def __init__(self, uuid: str, password: str, logger: logging.Logger) -> None:
        self.uuid = uuid.replace(":", "").lower()
        self.password = password
        self.logger = logger

        # State
        self.device: BLEDevice | None = None
        self.client: BleakClient | None = None
        self.conn_hash8: bytes | None = None
        self.header_mode: str | None = None
        self.tx_uuid: str | None = None
        self.notify_uuids: set[str] = set()
        self.tx_seq: int = 0
        self.tx_div: int = 1

        # Keys (populated from cloud if connected)
        self.visitor_key: bytes | None = None
        self.manager_key: bytes | None = None

        # Diagnostic history
        self.tx_history: list[dict[str, Any]] = []
        self.rx_history: list[dict[str, Any]] = []
        self.gatt_services: list[dict[str, Any]] = []
        self.errors: list[dict[str, Any]] = []

    async def discover(self, timeout: float = 10.0) -> BLEDevice | None:
        """Discover the Casambi device by UUID."""
        self.logger.info("[CLASSIC_DIAG_DISCOVER] Scanning for Casambi devices (timeout=%.1fs)...", timeout)

        target_uuid = self.uuid.lower()

        def match_callback(device: BLEDevice, adv_data: Any) -> bool:
            # Casambi embeds the network UUID in advertisement manufacturer data
            # or the device address itself may match for some setups.
            addr = device.address.replace(":", "").lower()
            if addr == target_uuid:
                return True
            # Also check manufacturer data for network UUID
            if hasattr(adv_data, "manufacturer_data"):
                for _id, data in adv_data.manufacturer_data.items():
                    if target_uuid in data.hex().lower():
                        return True
            return False

        devices = await BleakScanner.discover(timeout=timeout)
        self.logger.info("[CLASSIC_DIAG_DISCOVER] Found %d BLE devices", len(devices))

        # Find our target
        for d in devices:
            addr = d.address.replace(":", "").lower()
            if addr == target_uuid:
                self.logger.info("[CLASSIC_DIAG_DISCOVER] Found target device: %s (%s)", d.name, d.address)
                return d

        # Fallback: list all Casambi-looking devices
        casambi_devices = []
        for d in devices:
            name = d.name or ""
            if "casambi" in name.lower() or "casa" in name.lower():
                casambi_devices.append(d)

        if casambi_devices:
            self.logger.warning(
                "[CLASSIC_DIAG_DISCOVER] Target not found by UUID, but found %d Casambi devices: %s",
                len(casambi_devices),
                [(d.name, d.address) for d in casambi_devices[:5]],
            )
            # Return first one as fallback
            return casambi_devices[0]

        self.logger.error("[CLASSIC_DIAG_DISCOVER] No matching device found for UUID=%s", self.uuid)
        return None

    async def fetch_cloud_keys(self) -> None:
        """Attempt to fetch Classic keys from Casambi cloud API."""
        try:
            import httpx

            self.logger.info("[CLASSIC_DIAG_CLOUD] Fetching network info from cloud...")

            # Get network ID
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"https://api.casambi.com/network/uuid/{self.uuid}")
                if resp.status_code != 200:
                    self.logger.warning("[CLASSIC_DIAG_CLOUD] Failed to get network ID: %d", resp.status_code)
                    return

                network_id = resp.json().get("id")
                self.logger.info("[CLASSIC_DIAG_CLOUD] Network ID: %s", network_id)

                # Login
                resp = await client.post(
                    f"https://api.casambi.com/network/{network_id}/session",
                    json={"password": self.password, "deviceName": "ClassicDiagnostics", "token": "diag/test/python"},
                )
                if resp.status_code != 200:
                    self.logger.warning("[CLASSIC_DIAG_CLOUD] Failed to login: %d", resp.status_code)
                    return

                session = resp.json()
                session_token = session.get("session")
                is_manager = session.get("manager", False)
                self.logger.info("[CLASSIC_DIAG_CLOUD] Logged in, manager=%s", is_manager)

                # Get network details
                resp = await client.put(
                    f"https://api.casambi.com/network/{network_id}/",
                    json={"formatVersion": 1, "deviceName": "ClassicDiagnostics", "revision": 0},
                    headers={"X-Casambi-Session": session_token},
                )
                if resp.status_code != 200:
                    self.logger.warning("[CLASSIC_DIAG_CLOUD] Failed to get network: %d", resp.status_code)
                    return

                network_data = resp.json()
                network = network_data.get("network", {})

                # Extract Classic keys
                visitor_hex = network.get("visitorKey")
                manager_hex = network.get("managerKey")
                protocol_version = network.get("protocolVersion")

                self.logger.info(
                    "[CLASSIC_DIAG_CLOUD] protocolVersion=%s visitorKey=%s managerKey=%s",
                    protocol_version,
                    bool(visitor_hex),
                    bool(manager_hex),
                )

                if visitor_hex and isinstance(visitor_hex, str) and visitor_hex.strip():
                    try:
                        self.visitor_key = bytes.fromhex(visitor_hex.strip())
                    except ValueError:
                        pass

                if manager_hex and isinstance(manager_hex, str) and manager_hex.strip():
                    try:
                        self.manager_key = bytes.fromhex(manager_hex.strip())
                    except ValueError:
                        pass

        except ImportError:
            self.logger.warning("[CLASSIC_DIAG_CLOUD] httpx not installed, skipping cloud key fetch")
        except Exception as e:
            self.logger.warning("[CLASSIC_DIAG_CLOUD] Failed to fetch cloud keys: %s", e)

    async def connect(self, device: BLEDevice) -> bool:
        """Connect to the device and probe GATT characteristics."""
        self.device = device
        self.logger.info("[CLASSIC_DIAG_CONNECT] Connecting to %s (%s)...", device.name, device.address)

        try:
            self.client = BleakClient(device)
            await self.client.connect()
            self.logger.info("[CLASSIC_DIAG_CONNECT] Connected successfully")
        except Exception as e:
            self._record_error("connect", str(e))
            self.logger.error("[CLASSIC_DIAG_CONNECT] Failed to connect: %s", e)
            return False

        # Enumerate services
        await self._probe_gatt()

        # Probe for Classic characteristics
        await self._probe_classic()

        return self.conn_hash8 is not None

    async def _probe_gatt(self) -> None:
        """Enumerate and log all GATT services/characteristics."""
        self.logger.info("[CLASSIC_DIAG_GATT] Enumerating GATT services...")

        try:
            services = self.client.services
            for svc in services:
                svc_info: dict[str, Any] = {"uuid": str(svc.uuid), "chars": []}
                for char in svc.characteristics:
                    char_info = {
                        "uuid": str(char.uuid),
                        "properties": char.properties,
                        "handle": char.handle,
                    }
                    svc_info["chars"].append(char_info)
                self.gatt_services.append(svc_info)

                self.logger.info(
                    "[CLASSIC_DIAG_GATT] Service: %s (chars=%d)",
                    svc.uuid,
                    len(svc.characteristics),
                )
                for char in svc.characteristics:
                    self.logger.debug(
                        "[CLASSIC_DIAG_GATT]   Char: %s props=%s",
                        char.uuid,
                        char.properties,
                    )
        except Exception as e:
            self._record_error("gatt_enum", str(e))
            self.logger.warning("[CLASSIC_DIAG_GATT] Failed to enumerate services: %s", e)

    async def _probe_classic(self) -> None:
        """Probe for Classic protocol support and read connection hash."""

        # Try legacy CA51 (connection hash)
        try:
            data = await self.client.read_gatt_char(CASA_CLASSIC_HASH_CHAR_UUID)
            if data and len(data) >= 8:
                self.conn_hash8 = bytes(data[:8])
                self.header_mode = "legacy"
                self.tx_uuid = CASA_CLASSIC_DATA_CHAR_UUID
                self.logger.info(
                    "[CLASSIC_DIAG_CONNECT] Legacy Classic detected, conn_hash8=%s",
                    self.conn_hash8.hex(),
                )
        except Exception as e:
            self.logger.debug("[CLASSIC_DIAG_CONNECT] CA51 read failed: %s", e)

        # Try conformant (auth char read)
        if self.conn_hash8 is None:
            try:
                data = await self.client.read_gatt_char(CASA_AUTH_CHAR_UUID)
                if data and len(data) >= 8:
                    # If first byte is 0x01, it's EVO NodeInfo, not Classic
                    if data[0] != 0x01:
                        self.conn_hash8 = bytes(data[:8])
                        self.header_mode = "conformant"
                        self.tx_uuid = CASA_AUTH_CHAR_UUID
                        self.logger.info(
                            "[CLASSIC_DIAG_CONNECT] Conformant Classic detected, conn_hash8=%s",
                            self.conn_hash8.hex(),
                        )
                    else:
                        self.logger.warning(
                            "[CLASSIC_DIAG_CONNECT] EVO device detected (NodeInfo 0x01), not Classic"
                        )
            except Exception as e:
                self.logger.debug("[CLASSIC_DIAG_CONNECT] Auth char read failed: %s", e)

        if self.conn_hash8 is None:
            self._record_error("no_classic", "Could not detect Classic protocol")
            self.logger.error("[CLASSIC_DIAG_CONNECT] Failed to detect Classic protocol")
            return

        # Log key status
        self.logger.warning(
            "[CLASSIC_DIAG_KEYS] visitor=%s manager=%s",
            self.visitor_key is not None,
            self.manager_key is not None,
        )

        # Subscribe to notifications
        await self._subscribe_notifications()

    async def _subscribe_notifications(self) -> None:
        """Subscribe to Classic notification channels."""

        def notify_handler(handle: Any, data: bytes) -> None:
            self._record_rx(handle, data)

        notify_targets = []
        if self.header_mode == "legacy":
            notify_targets = [
                (CASA_CLASSIC_DATA_CHAR_UUID, "ca52"),
                (CASA_CLASSIC_CA53_CHAR_UUID, "ca53"),
            ]
        else:
            notify_targets = [
                (CASA_AUTH_CHAR_UUID, "auth"),
                (CASA_CLASSIC_CONFORMANT_CA53_CHAR_UUID, "0003"),
            ]

        for uuid, name in notify_targets:
            try:
                await self.client.start_notify(uuid, notify_handler)
                self.notify_uuids.add(uuid.lower())
                self.logger.info("[CLASSIC_DIAG_SUBSCRIBE] Subscribed to %s (%s)", name, uuid)
            except Exception as e:
                self.logger.debug("[CLASSIC_DIAG_SUBSCRIBE] Failed to subscribe %s: %s", name, e)

    def _record_rx(self, handle: Any, data: bytes) -> None:
        """Record received notification."""
        ts = time.time()
        entry = {
            "timestamp": ts,
            "iso_time": datetime.fromtimestamp(ts).isoformat(),
            "handle": str(getattr(handle, "uuid", handle)),
            "length": len(data),
            "hex": data.hex(),
        }
        self.rx_history.append(entry)

        # Log first 20 then every 10th
        if len(self.rx_history) <= 20 or len(self.rx_history) % 10 == 0:
            self.logger.warning(
                "[CLASSIC_DIAG_RX] #%d len=%d hex=%s",
                len(self.rx_history),
                len(data),
                data[:32].hex() + ("..." if len(data) > 32 else ""),
            )

    def _record_tx(self, uuid: str, data_pre: bytes, data_post: bytes, result: str) -> None:
        """Record transmitted packet."""
        ts = time.time()
        entry = {
            "timestamp": ts,
            "iso_time": datetime.fromtimestamp(ts).isoformat(),
            "uuid": uuid,
            "pre_sign_hex": data_pre.hex(),
            "post_sign_hex": data_post.hex(),
            "length": len(data_post),
            "result": result,
        }
        self.tx_history.append(entry)
        self.logger.warning(
            "[CLASSIC_DIAG_TX_POST] #%d len=%d result=%s hex=%s",
            len(self.tx_history),
            len(data_post),
            result,
            data_post.hex(),
        )

    def _record_error(self, context: str, message: str) -> None:
        """Record an error."""
        ts = time.time()
        self.errors.append({
            "timestamp": ts,
            "iso_time": datetime.fromtimestamp(ts).isoformat(),
            "context": context,
            "message": message,
        })

    def _next_seq(self) -> int:
        """Get next 16-bit sequence number."""
        self.tx_seq = (self.tx_seq + 1) & 0xFFFF
        if self.tx_seq == 0:
            self.tx_seq = 1
        return self.tx_seq

    def _next_div(self) -> int:
        """Get next 8-bit command divider."""
        self.tx_div = (self.tx_div + 1) & 0xFF
        if self.tx_div == 0:
            self.tx_div = 1
        return self.tx_div

    def _build_command_record(
        self,
        ordinal: int,
        payload: bytes,
        target_id: int | None = None,
        lifetime: int = 200,
    ) -> bytes:
        """Build a Classic command record (u1.C1753e format)."""
        div = self._next_div()
        b = bytearray()
        b.append(0)  # placeholder for encoded length
        b.append(0)  # placeholder for type flags

        type_flags = ordinal & 0x3F
        b.append(div & 0xFF)
        type_flags |= 0x40  # div present

        if target_id is not None and target_id > 0:
            b.append(target_id & 0xFF)
            type_flags |= 0x80  # target present

        b.append(lifetime & 0xFF)
        b.extend(payload)

        msg_len = len(b)
        b[0] = (msg_len + 239) & 0xFF
        b[1] = type_flags & 0xFF

        return bytes(b)

    def _build_simple_command(
        self,
        unit_id: int,
        dimmer: int,
        extra: int = 0,
    ) -> bytes:
        """Build a Classic command using the simple format from BLE captures.

        Format (before header): [counter:1][unit_id:1][param_len:1][dimmer:1][extra:1?]
        """
        counter = self._next_div()
        if extra != 0:
            return bytes([counter, unit_id, 2, dimmer & 0xFF, extra & 0xFF])
        else:
            return bytes([counter, unit_id, 1, dimmer & 0xFF])

    async def send_classic_command(self, command_bytes: bytes, *, use_simple_format: bool = False) -> bool:
        """Send a Classic command with proper framing and CMAC signing."""
        if self.conn_hash8 is None or self.tx_uuid is None:
            self.logger.error("[CLASSIC_DIAG_TX] Cannot send: not connected to Classic device")
            return False

        # Select key
        key = self.visitor_key or self.manager_key
        key_name = "visitor" if key == self.visitor_key else ("manager" if key else "none")
        auth_level = 0x03 if key == self.manager_key else 0x02

        # Pre-signing packet for logging
        pre_sign = command_bytes

        # Build header based on mode
        pkt = bytearray()
        if self.header_mode == "conformant":
            sig_len = 16 if auth_level == 0x03 else 4
            seq = self._next_seq()

            pkt.append(auth_level)
            pkt.extend(b"\x00" * sig_len)
            pkt.extend(b"\x00\x00")
            pkt.extend(command_bytes)

            seq_off = 1 + sig_len
            pkt[seq_off] = (seq >> 8) & 0xFF
            pkt[seq_off + 1] = seq & 0xFF

            if key is not None:
                cmac_input = bytes(pkt[seq_off:])
                prefix = classic_cmac_prefix(key, self.conn_hash8, cmac_input, sig_len)
                pkt[1 : 1 + sig_len] = prefix

        elif self.header_mode == "legacy":
            sig_len = 4
            pkt.extend(b"\x00" * sig_len)
            pkt.extend(command_bytes)

            if key is not None:
                cmac_input = bytes(command_bytes)
                prefix = classic_cmac_prefix(key, self.conn_hash8, cmac_input, sig_len)
                pkt[0:sig_len] = prefix

        else:
            self.logger.error("[CLASSIC_DIAG_TX] Unknown header mode: %s", self.header_mode)
            return False

        self.logger.warning(
            "[CLASSIC_DIAG_TX_PRE] header=%s key=%s auth=0x%02x cmd_len=%d hex=%s",
            self.header_mode,
            key_name,
            auth_level,
            len(command_bytes),
            command_bytes.hex(),
        )

        # Send
        try:
            await self.client.write_gatt_char(self.tx_uuid, bytes(pkt), response=True)
            self._record_tx(self.tx_uuid, pre_sign, bytes(pkt), "ok")
            self.logger.warning("[CLASSIC_DIAG_TX_RESULT] success len=%d", len(pkt))
            return True
        except Exception as e:
            self._record_tx(self.tx_uuid, pre_sign, bytes(pkt), f"error: {e}")
            self.logger.error("[CLASSIC_DIAG_TX_RESULT] failed: %s", e)
            return False

    async def set_level_all(self, level: int) -> None:
        """Set level on all units."""
        self.logger.info("[CLASSIC_DIAG_CMD] Setting level=%d on all units (record format)", level)
        payload = bytes([level & 0xFF])
        cmd = self._build_command_record(4, payload)  # AllUnitsLevel = 4
        await self.send_classic_command(cmd)

    async def set_level_all_simple(self, level: int) -> None:
        """Set level on all units using simple format."""
        self.logger.info("[CLASSIC_DIAG_CMD] Setting level=%d on all units (simple format)", level)
        # Simple format: unit_id=0xFF for "all units"
        cmd = self._build_simple_command(0xFF, level)
        await self.send_classic_command(cmd, use_simple_format=True)

    async def run_diagnostics(self) -> None:
        """Run the full diagnostic sequence."""
        use_simple = os.environ.get("CASAMBI_BT_CLASSIC_FORMAT", "").lower() == "simple"

        self.logger.info("[CLASSIC_DIAG] Starting diagnostic sequence...")
        self.logger.info("[CLASSIC_DIAG] Using %s packet format", "simple" if use_simple else "record")

        # Test 1: Set level 0
        self.logger.info("[CLASSIC_DIAG] Test 1: Set level 0")
        if use_simple:
            await self.set_level_all_simple(0)
        else:
            await self.set_level_all(0)

        self.logger.info("[CLASSIC_DIAG] Waiting 5 seconds for state updates...")
        await asyncio.sleep(5)

        # Test 2: Set level 255
        self.logger.info("[CLASSIC_DIAG] Test 2: Set level 255")
        if use_simple:
            await self.set_level_all_simple(255)
        else:
            await self.set_level_all(255)

        self.logger.info("[CLASSIC_DIAG] Waiting 5 seconds for state updates...")
        await asyncio.sleep(5)

        # Test 3: Set level 0 again
        self.logger.info("[CLASSIC_DIAG] Test 3: Set level 0")
        if use_simple:
            await self.set_level_all_simple(0)
        else:
            await self.set_level_all(0)

        self.logger.info("[CLASSIC_DIAG] Waiting 3 seconds...")
        await asyncio.sleep(3)

        # If not using simple, also try simple format for comparison
        if not use_simple:
            self.logger.info("[CLASSIC_DIAG] Test 4: Trying simple format for comparison")
            await self.set_level_all_simple(128)
            await asyncio.sleep(2)
            await self.set_level_all_simple(0)
            await asyncio.sleep(2)

        self.logger.info("[CLASSIC_DIAG] Diagnostic sequence complete")

    async def disconnect(self) -> None:
        """Disconnect from the device."""
        if self.client and self.client.is_connected:
            try:
                await self.client.disconnect()
                self.logger.info("[CLASSIC_DIAG_DISCONNECT] Disconnected")
            except Exception as e:
                self.logger.warning("[CLASSIC_DIAG_DISCONNECT] Error: %s", e)

    def generate_report(self) -> dict[str, Any]:
        """Generate the diagnostic report."""
        return {
            "generated_at": datetime.now().isoformat(),
            "uuid": self.uuid,
            "device": {
                "name": self.device.name if self.device else None,
                "address": self.device.address if self.device else None,
            },
            "protocol": {
                "header_mode": self.header_mode,
                "conn_hash8": self.conn_hash8.hex() if self.conn_hash8 else None,
                "tx_uuid": self.tx_uuid,
                "notify_uuids": list(self.notify_uuids),
            },
            "keys": {
                "visitor_present": self.visitor_key is not None,
                "manager_present": self.manager_key is not None,
            },
            "gatt_services": self.gatt_services,
            "statistics": {
                "tx_count": len(self.tx_history),
                "rx_count": len(self.rx_history),
                "error_count": len(self.errors),
            },
            "tx_history": self.tx_history[-50:],  # Last 50 TX
            "rx_history": self.rx_history[-50:],  # Last 50 RX
            "errors": self.errors,
        }


async def main() -> int:
    parser = argparse.ArgumentParser(
        description="Classic Casambi protocol diagnostic tool",
        epilog="""
Examples:
    python classic_diagnostics.py CE42027B8FDE mypassword
    python classic_diagnostics.py CE42027B8FDE mypassword --output diag.log

Environment variables:
    CASAMBI_BT_CLASSIC_FORMAT=simple  Use alternative simple packet format
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("uuid", help="Network UUID (12 hex chars, e.g., CE42027B8FDE)")
    parser.add_argument("password", help="Network password")
    parser.add_argument("--output", "-o", help="Output log file (default: classic_diag_<timestamp>.log)")
    parser.add_argument("--timeout", "-t", type=float, default=10.0, help="BLE scan timeout in seconds")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # Setup logging
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = args.output or f"classic_diag_{timestamp}.log"

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file),
        ],
    )
    logger = logging.getLogger("ClassicDiag")
    logger.info("=" * 60)
    logger.info("CLASSIC CASAMBI PROTOCOL DIAGNOSTICS")
    logger.info("=" * 60)
    logger.info("UUID: %s", args.uuid)
    logger.info("Log file: %s", log_file)
    logger.info("Format: %s", os.environ.get("CASAMBI_BT_CLASSIC_FORMAT", "record"))
    logger.info("=" * 60)

    diag = ClassicDiagnostics(args.uuid, args.password, logger)

    try:
        # Fetch cloud keys first
        await diag.fetch_cloud_keys()

        # Discover device
        device = await diag.discover(timeout=args.timeout)
        if not device:
            logger.error("Device not found. Make sure the network is in range.")
            return 1

        # Connect
        if not await diag.connect(device):
            logger.error("Failed to connect or detect Classic protocol.")
            return 1

        # Run diagnostics
        await diag.run_diagnostics()

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.exception("Unexpected error: %s", e)
    finally:
        await diag.disconnect()

        # Generate and save report
        report = diag.generate_report()
        report_file = log_file.replace(".log", "_report.json")
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)
        logger.info("Report saved to: %s", report_file)

        # Summary
        logger.info("=" * 60)
        logger.info("SUMMARY")
        logger.info("=" * 60)
        logger.info("TX packets sent: %d", len(diag.tx_history))
        logger.info("RX packets received: %d", len(diag.rx_history))
        logger.info("Errors: %d", len(diag.errors))
        logger.info("Log file: %s", log_file)
        logger.info("Report file: %s", report_file)
        logger.info("=" * 60)

        if len(diag.rx_history) == 0:
            logger.warning("NO RX PACKETS RECEIVED - Classic notifications may not be working")
            logger.warning("Check that the network supports Classic protocol")

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
