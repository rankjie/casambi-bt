#!/usr/bin/env python3
"""Run a local network event viewer using the library checkout."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import json
import logging
import os
import signal
import sys
from collections import deque
from collections.abc import Awaitable, Callable
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import httpx
from aiohttp import web
from anyio import Path as AsyncPath
from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from CasambiBt import Casambi, Unit, discover  # noqa: E402
from CasambiBt._cache import CACHE_VERSION, Cache  # noqa: E402
from CasambiBt._client import CasambiClient  # noqa: E402
from CasambiBt._network import Network  # noqa: E402
from CasambiBt._network_events import input_observation  # noqa: E402


class EventBuffer:
    """Keep bounded event history and wake WebSocket subscribers on changes."""

    def __init__(self, capacity: int = 5000, history_path: Path | None = None) -> None:
        """Create a history for one server session."""
        self.rows: deque[dict] = deque(maxlen=capacity)
        self.session = uuid4().hex
        self.subscribers: set[asyncio.Event] = set()
        self.sequence = 0
        self.status: dict = {"state": "starting", "message": "正在连接本地蓝牙网络…"}
        self.history_path = history_path
        if history_path is not None and history_path.exists():
            with history_path.open(encoding="utf-8") as history:
                for line_number, line in enumerate(history, 1):
                    try:
                        record = json.loads(line)
                        row = record["event"]
                        row.update(input_observation(row))
                        if row["id"] != self.sequence + 1:
                            raise ValueError("Non-sequential event ID")
                        self.session = record["session"]
                        self.rows.append(row)
                        self.sequence = row["id"]
                    except (ValueError, KeyError, TypeError) as error:
                        raise ValueError(
                            f"Invalid event history at line {line_number}"
                        ) from error

    def append(self, event: dict) -> None:
        """Retain one decoded event with a monotonically increasing cursor."""
        row = {**event, "id": self.sequence + 1}
        if self.history_path is not None:
            record = (
                json.dumps({"session": self.session, "event": row}, ensure_ascii=False)
                + "\n"
            )
            try:
                fd = os.open(
                    self.history_path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600
                )
                with os.fdopen(fd, "a", encoding="utf-8") as history:
                    history.write(record)
                    history.flush()
            except OSError:
                self.set_status(
                    state="failed",
                    message="事件历史写入失败，采集未能保存。请检查磁盘空间和目录权限。",
                )
                raise
        self.sequence += 1
        self.rows.append(row)
        for wake in self.subscribers:
            wake.set()

    def set_status(self, **status: object) -> None:
        """Publish connection state without credentials or raw configuration."""
        self.status.update(status)
        for wake in self.subscribers:
            wake.set()

    def snapshot(self, after: int = 0) -> dict:
        """Return retained events after a cursor, plus explicit retention limits."""
        oldest = self.rows[0]["id"] if self.rows else self.sequence + 1
        return {
            "session": self.session,
            "status": dict(self.status),
            "events": [dict(row) for row in self.rows if row["id"] > after],
            "cursor": self.sequence,
            "retained": len(self.rows),
            "capacity": self.rows.maxlen,
            "expired": max(0, self.sequence - len(self.rows)),
            "missed": max(0, oldest - after - 1) if after else 0,
        }

    def export(self) -> list[dict]:
        """Export all persisted events, including rows older than the live window."""
        if self.history_path is None:
            return list(self.rows)
        if not self.history_path.exists():
            return []
        with self.history_path.open(encoding="utf-8") as history:
            return [json.loads(line)["event"] for line in history]


class _ExistingCache(Cache):
    """Let the library read its existing cache without migration or directory creation."""

    async def __aenter__(self) -> AsyncPath:
        if self._uuid is None:
            raise ValueError("Network UUID is required")
        if not await self._cacheVersionFile.exists():
            raise FileNotFoundError("Existing Casambi cache is required")
        if int(await self._cacheVersionFile.read_text()) != CACHE_VERSION:
            raise ValueError("Existing cache version is unsupported")
        path = self._cachePath / self._uuid
        if not await path.is_dir():
            raise FileNotFoundError("This network has no existing local cache")
        return path

    async def __aexit__(self, *_args: object) -> None:
        return None


class _ProtocolErrors(logging.Handler):
    """Expose library failures without formatting logs containing protocol secrets."""

    def __init__(self, buffer: EventBuffer) -> None:
        """Bind diagnostic status to this event viewer."""
        super().__init__(level=logging.ERROR)
        self.buffer = buffer
        self.count = 0

    def emit(self, record: logging.LogRecord) -> None:
        """Publish only module identity, severity and exception class."""
        self.count += 1
        error_type = (
            record.exc_info[0].__name__
            if record.exc_info and record.exc_info[0]
            else record.levelname
        )
        self.buffer.set_status(
            protocol_errors=self.count, protocol_error=f"{record.name}: {error_type}"
        )


class ReceiveDiagnostics:
    """Record packet metadata and decoder decisions without protocol payloads."""

    def __init__(self, buffer: EventBuffer, path: Path | None) -> None:
        """Start a fresh receive session independently of retained event history."""
        self.buffer, self.path = buffer, path
        self.session = uuid4().hex
        self.received = self.invalid = self.type7 = 0
        self.copies = self.paired = self.emitted = 0
        self.callback_errors = 0
        self.last_sequence: int | None = None
        self.connection: dict = {}

    def record(self, diagnostic: dict) -> None:
        """Persist the library's explicit metadata contract and publish counters."""
        now = datetime.now().astimezone().isoformat(timespec="milliseconds")
        record = {"session": self.session, "timestamp": now, **diagnostic}
        if diagnostic["stage"] == "evo_receive":
            self.received += 1
            self.invalid += int(not diagnostic["verified"])
            self.type7 += int(diagnostic["packet_type"] == 7)
            sequence = diagnostic["packet_sequence"]
            if diagnostic["verified"] and sequence is not None:
                if self.last_sequence is not None:
                    record["sequence_delta"] = (
                        sequence - self.last_sequence
                    ) & 0x7FFFFFFF
                self.last_sequence = sequence
        elif diagnostic["stage"] == "switch_decode":
            self.copies += diagnostic["suppressed_copies"]
            self.paired += diagnostic["suppressed_paired"]
            self.emitted += diagnostic["legacy_emitted"]
        elif diagnostic["stage"] == "callback_error":
            self.callback_errors += 1
        elif diagnostic["stage"] == "connection":
            self.connection = {
                key: diagnostic[key]
                for key in ("gateway_unit", "device_protocol", "handshake_trailer")
            }
        else:
            raise ValueError("Unknown receive diagnostic stage")
        if self.path is not None:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as history:
                    history.write(json.dumps(record) + "\n")
            except OSError:
                self.buffer.set_status(
                    state="failed",
                    message="接收诊断写入失败；请检查磁盘空间和目录权限。",
                )
                raise
        self.buffer.set_status(
            receive={
                "session": self.session,
                "packets": self.received,
                "invalid_signatures": self.invalid,
                "callback_errors": self.callback_errors,
                "type7_packets": self.type7,
                "last_sequence": self.last_sequence,
                "last_received": now,
                "legacy_emitted": self.emitted,
                "legacy_copies": self.copies,
                "legacy_paired": self.paired,
                **self.connection,
            }
        )


def select_gateway(
    advertisements: dict[str, tuple[BLEDevice, AdvertisementData]],
    network_address: str,
    unit_id: int,
) -> BLEDevice:
    """Select a node using the official short/long advertisement network identity."""
    reference = next(
        (
            adv.manufacturer_data.get(963)
            for device, adv in advertisements.values()
            if device.address.lower() == network_address.lower()
        ),
        None,
    )
    if reference is None or not 7 <= len(reference) < 22:
        raise ConnectionError("The configured network advertisement is not visible")
    network_id = reference[:6]
    candidates = []
    for device, adv in advertisements.values():
        payload = adv.manufacturer_data.get(963)
        # Official ip.s's node branch reads 23 bytes, despite its >=22 dispatch.
        if payload is None or len(payload) < 23:
            continue
        if payload[12:18] == network_id and payload[18] == unit_id:
            if (payload[19] & 31) < 10:
                raise ValueError("The selected gateway does not advertise EVO")
            candidates.append(device)
    if len(candidates) != 1:
        raise ConnectionError(
            f"Expected one gateway for unit {unit_id}; found {len(candidates)}"
        )
    return candidates[0]


async def connect_cached(
    casa: Casambi,
    address: str,
    cache_path: Path,
    buffer: EventBuffer,
    diagnostics: ReceiveDiagnostics | None = None,
    gateway_unit: int | None = None,
) -> None:
    """Use cached EVO keys through the library; refresh only public fixture profiles.

    Network.load() reads the original cache normally. Network.update()/logIn()
    are deliberately not invoked: those methods persist sessions, keys or types.
    This diagnostic does not change the existing store or mesh configuration.
    """
    cache = _ExistingCache(cache_path)
    await cache.setUuid(address.replace(":", "").lower())
    client = httpx.AsyncClient(timeout=20)
    casa._httpClient = client
    network = Network(address.replace(":", "").lower(), client, cache)
    await network.load()
    async with cache as path:
        network._id = (await (path / "networkid").read_text()).strip()
        data = json.loads(await (path / f"{network._id}.json").read_bytes())
    profile = data["network"]
    if "keyStore" not in profile:
        raise ValueError("Network Events requires an Evolution network")
    network._networkName = profile["name"]
    network._networkRevision = profile["revision"]
    network._protocolVersion = profile["protocolVersion"]
    network._grade = profile.get("grade")
    network._unitTypes.clear()
    for item in profile["units"]:
        fixture = await network._fetchUnitInfo(item["type"])
        if fixture is None:
            raise ValueError(f"Public fixture {item['type']} is unavailable")
        network.units.append(
            Unit(
                item["type"],
                item["deviceID"],
                item["uuid"],
                item["address"],
                item["name"],
                str(item["firmware"]),
                fixture,
                networkProtocolVersion=network._protocolVersion,
                networkGrade=network._grade,
            )
        )
    casa._casaNetwork = network
    buffer.set_status(
        state="scanning",
        network=network._networkName,
        units=len(network.units),
        message="正在扫描 Mac 附近的 Casambi 网络…",
    )
    if gateway_unit is None:
        devices = await discover()
        device = next(
            (d for d in devices if d.address.lower() == address.lower()), None
        )
        if device is None:
            raise ConnectionError("Mac did not discover the configured Casambi network")
    else:
        advertisements = await BleakScanner.discover(
            return_adv=True, cb={"use_bdaddr": True}
        )
        device = select_gateway(advertisements, address, gateway_unit)
    casa._casaClient = CasambiClient(
        device,
        casa._dataCallback,
        casa._disconnectCallback,
        network,
        invocationCallback=casa._invocationCallback,
        receiveDiagnosticCallback=(
            diagnostics.record if diagnostics is not None else None
        ),
    )
    await casa._connectClient()
    if gateway_unit is not None and casa._casaClient._unit != gateway_unit:
        raise ValueError("Connected NodeInfo does not match the selected gateway unit")
    if diagnostics is not None:
        diagnostics.record(
            {
                "stage": "connection",
                "gateway_unit": casa._casaClient._unit,
                "device_protocol": casa._casaClient._deviceProtocolVersion,
                "handshake_trailer": "0d01",
            }
        )


def make_app(
    buffer: EventBuffer, lan_addresses: tuple[str, ...] = ()
) -> web.Application:
    """Serve HTTP and WebSocket updates on the explicitly selected local interfaces."""
    sockets: set[web.WebSocketResponse] = set()
    allowed_hosts = {"127.0.0.1", "localhost"}
    allowed_hosts.update(lan_addresses)

    @web.middleware
    async def local_only(
        request: web.Request,
        handler: Callable[[web.Request], Awaitable[web.StreamResponse]],
    ) -> web.StreamResponse:
        host = request.host
        if host.split(":")[0] not in allowed_hosts:
            raise web.HTTPForbidden()
        origin = request.headers.get("Origin")
        if origin and origin != f"http://{host}":
            raise web.HTTPForbidden()
        response = await handler(request)
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": f"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self' ws://{host}; object-src 'none'; frame-ancestors 'none'",
            }
        )
        return response

    def cursor(request: web.Request) -> int:
        try:
            after = int(request.query.get("after", "0"))
            if after < 0:
                raise ValueError("Negative cursor")
            return after
        except ValueError as error:
            raise web.HTTPBadRequest(text="Invalid cursor") from error

    async def index(_request: web.Request) -> web.Response:
        return web.Response(
            body=Path(__file__).with_name("network_events_demo.html").read_bytes(),
            content_type="text/html",
            charset="utf-8",
        )

    async def events(request: web.Request) -> web.Response:
        return web.json_response(buffer.snapshot(cursor(request)))

    async def export(_request: web.Request) -> web.Response:
        return web.json_response(
            buffer.export(),
            headers={
                "Content-Disposition": 'attachment; filename="casambi-network-events.json"'
            },
        )

    async def websocket(request: web.Request) -> web.WebSocketResponse:
        after = cursor(request)
        reset = (
            request.query.get("session") != buffer.session or after > buffer.sequence
        )
        if reset:
            after = 0
        ws = web.WebSocketResponse(heartbeat=20, max_msg_size=1024)
        await ws.prepare(request)
        sockets.add(ws)
        wake = asyncio.Event()
        buffer.subscribers.add(wake)

        async def send_updates() -> None:
            nonlocal after, reset
            try:
                while not ws.closed:
                    wake.clear()
                    snapshot = buffer.snapshot(after)
                    snapshot["reset"] = reset
                    async with asyncio.timeout(10):
                        await ws.send_json(snapshot)
                    after = snapshot["cursor"]
                    reset = False
                    await wake.wait()
            finally:
                await ws.close()

        sender = asyncio.create_task(send_updates())
        try:
            async for _message in ws:
                # This is a receive-only viewer; no mesh commands are exposed.
                await ws.close(code=1008, message=b"Read-only stream")
        finally:
            buffer.subscribers.discard(wake)
            sockets.discard(ws)
            sender.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sender
        return ws

    async def shutdown(_app: web.Application) -> None:
        for ws in set(sockets):
            await ws.close(code=1001, message=b"Server shutdown")

    app = web.Application(middlewares=[local_only])
    app.add_routes(
        [
            web.get("/", index),
            web.get("/api/events", events),
            web.get("/export.json", export),
            web.get("/ws", websocket),
        ]
    )
    app.on_shutdown.append(shutdown)
    return app


async def main() -> None:
    """Start the viewer and leave the live stream running until SIGINT/SIGTERM."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--address", required=True, help="Existing cached network BLE MAC address"
    )
    parser.add_argument("--cache-path", type=Path, default=ROOT / "casambi-bt-store")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--gateway-unit",
        type=int,
        help="Connect through this same-network EVO node instead of the network endpoint",
    )
    parser.add_argument(
        "--event-log",
        type=Path,
        default=ROOT / "network-events.jsonl",
        help="Persist decoded events across demo restarts",
    )
    parser.add_argument(
        "--lan-address",
        action="append",
        default=[],
        help="Also listen on this Mac's private LAN IPv4 address (repeatable)",
    )
    args = parser.parse_args()
    if args.gateway_unit is not None and not 1 <= args.gateway_unit <= 255:
        parser.error("--gateway-unit must be between 1 and 255")
    for address in args.lan_address:
        lan_ip = ipaddress.IPv4Address(address)
        if not lan_ip.is_private or lan_ip.is_loopback or lan_ip.is_unspecified:
            parser.error("--lan-address must be a private LAN IPv4 address")
    logging.basicConfig(level=logging.ERROR)
    buffer = EventBuffer(history_path=args.event_log)
    diagnostics = ReceiveDiagnostics(
        buffer, args.event_log.with_suffix(".receive.jsonl")
    )
    # Verbose protocol logs include authentication material. Forward error metadata
    # without formatting their messages, parameters, exception text or traceback.
    protocol_logger = logging.getLogger("CasambiBt")
    protocol_logger.setLevel(logging.ERROR)
    protocol_logger.handlers = [_ProtocolErrors(buffer)]
    protocol_logger.propagate = False
    runner = web.AppRunner(make_app(buffer, tuple(args.lan_address)), access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", args.port).start()
    for address in args.lan_address:
        await web.TCPSite(runner, address, args.port).start()
    print(  # noqa: T201
        f"Network Events (WebSocket): http://127.0.0.1:{args.port}", flush=True
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    casa = Casambi()
    casa.registerNetworkEventHandler(buffer.append)
    casa.registerDisconnectCallback(
        lambda: buffer.set_status(
            state="disconnected",
            message="蓝牙已断开；现有事件仍可查看和导出。重启 demo 可重新连接。",
        )
    )
    try:
        try:
            async with asyncio.timeout(90):
                await connect_cached(
                    casa,
                    args.address,
                    args.cache_path,
                    buffer,
                    diagnostics,
                    gateway_unit=args.gateway_unit,
                )
            buffer.set_status(
                state="connected", message="已连接本地蓝牙，正在接收真实网络事件。"
            )
            print(  # noqa: T201
                "Connected; live network events are available in the viewer.",
                flush=True,
            )
        except Exception as error:
            # The UI is a recovery boundary: retain history and show failure explicitly.
            # Exception payloads from the existing client can contain cloud responses.
            buffer.set_status(
                state="failed",
                message=f"连接失败：{type(error).__name__}。请确认网络在 Mac 蓝牙范围内且缓存可用。",
            )
            print(  # noqa: T201
                f"Connection failed ({type(error).__name__}); viewer remains available.",
                flush=True,
            )
        await stop.wait()
    finally:
        await casa.disconnect()
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
