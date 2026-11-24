"""Offline-first connect, cloud fallbacks, network refresh and offline backups.

The real connect path runs against a fake Casambi cloud and a real cache in a
temporary directory; only the bluetooth client is replaced.
"""

import json
import pickle
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from CasambiBt import Casambi  # noqa: E402
from CasambiBt.errors import (  # noqa: E402
    AuthenticationError,
    CloudUnavailableError,
    NetworkOnlineUpdateNeededError,
    OfflineBackupError,
)

ADDRESS = "AA:BB:CC:DD:EE:01"
UUID = "aabbccddee01"
NETWORK_ID = "synthetic-network-id"
PASSWORD = "synthetic-password"

FIXTURE = {
    "id": 4711,
    "model": "Synthetic dimmer",
    "vendor": "Test",
    "mode": "Dimmer",
    "stateLength": 1,
    "controls": [
        {"type": "dimmer", "offset": 0, "length": 8, "default": 0, "readonly": False}
    ],
    "events": {"synthetic": True},
}


def _network(revision: int, unitNames: list[str]) -> dict:
    return {
        "status": "OK",
        "network": {
            "revision": revision,
            "name": "Synthetic network",
            "protocolVersion": 10,
            "keyStore": {
                "keys": [
                    {"id": 1, "type": 1, "role": 3, "name": "m", "key": "00" * 16}
                ]
            },
            "units": [
                {
                    "type": FIXTURE["id"],
                    "deviceID": i + 1,
                    "uuid": f"{i:012x}",
                    "address": f"{i:012x}",
                    "name": name,
                    "firmware": "1.0",
                }
                for i, name in enumerate(unitNames)
            ],
            "grid": {"cells": []},
            "scenes": [],
        },
    }


class FakeCloud:
    """Answers like the Casambi cloud; `mode` selects a failure."""

    def __init__(self) -> None:
        """Start healthy with one lamp."""
        self.network = _network(1, ["Lamp"])
        self.mode = "ok"
        self.requests: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        """Answer one request."""
        path = request.url.path
        self.requests.append(f"{request.method} {path}")
        if self.mode == "down":
            raise httpx.ConnectError("synthetic outage", request=request)
        if self.mode == "503":
            return httpx.Response(503)
        if path == f"/network/uuid/{UUID}":
            return httpx.Response(200, json={"id": NETWORK_ID})
        if path == f"/network/{NETWORK_ID}/session":
            if self.mode == "401" or json.loads(request.content)["password"] != PASSWORD:
                return httpx.Response(401)
            return httpx.Response(
                200,
                json={
                    "session": "synthetic-session",
                    "network": NETWORK_ID,
                    "manager": True,
                    "keyID": 1,
                    "expires": int((time.time() + 3600) * 1000),
                },
            )
        if path == f"/network/{NETWORK_ID}/":
            if self.mode == "410":
                return httpx.Response(410)
            revision = json.loads(request.content)["revision"]
            if revision == self.network["network"]["revision"]:
                return httpx.Response(200, json={"status": "UPTODATE"})
            return httpx.Response(200, json=self.network)
        if path == f"/fixture/{FIXTURE['id']}":
            return httpx.Response(200, json=FIXTURE)
        return httpx.Response(404)


class OfflineTest(unittest.IsolatedAsyncioTestCase):
    """Connect, refresh and restore against the fake cloud."""

    def setUp(self) -> None:
        """Use a fake cloud, a temporary cache and no bluetooth."""
        self._tmp = tempfile.TemporaryDirectory()
        self.cacheDir = Path(self._tmp.name) / "store" / "casambi"
        self.cloud = FakeCloud()
        self._client = httpx.AsyncClient(
            transport=httpx.MockTransport(self.cloud.handler)
        )
        patcher = patch.object(Casambi, "_connectClient", new_callable=AsyncMock)
        patcher.start()
        self.addCleanup(patcher.stop)
        clientPatcher = patch("CasambiBt._casambi.CasambiClient")
        clientPatcher.start()
        self.addCleanup(clientPatcher.stop)

    async def asyncTearDown(self) -> None:
        """Close the http client and remove the cache."""
        await self._client.aclose()
        self._tmp.cleanup()

    def casa(self, cacheDir: Path | None = None) -> Casambi:
        """Return a client on the given cache directory."""
        return Casambi(self._client, cacheDir or self.cacheDir)

    async def test_prefer_cache_starts_without_the_cloud(self) -> None:
        """A cached network starts without any cloud request."""
        await self.casa().connect(ADDRESS, PASSWORD)
        self.cloud.requests.clear()

        casa = self.casa()
        await casa.connect(ADDRESS, PASSWORD, preferCache=True)

        self.assertEqual(self.cloud.requests, [])
        self.assertEqual([u.name for u in casa.units], ["Lamp"])
        self.assertIsNotNone(casa.rawNetworkData)

    async def test_prefer_cache_uses_the_cloud_without_cache(self) -> None:
        """Without a cache, preferCache still loads from the cloud."""
        casa = self.casa()
        await casa.connect(ADDRESS, PASSWORD, preferCache=True)
        self.assertIn(f"POST /network/{NETWORK_ID}/session", self.cloud.requests)
        self.assertEqual(casa.networkRevision, 1)

    async def test_cloud_errors_fall_back_to_the_cache(self) -> None:
        """Outages and 5xx answers keep a cached network working."""
        await self.casa().connect(ADDRESS, PASSWORD)
        # Force a new login so the login itself hits the failing cloud.
        (self.cacheDir / UUID / "session.pck").unlink()

        for mode in ("down", "503"):
            with self.subTest(mode=mode):
                self.cloud.mode = mode
                casa = self.casa()
                await casa.connect(ADDRESS, PASSWORD)
                self.assertEqual([u.name for u in casa.units], ["Lamp"])

    async def test_cloud_errors_without_cache(self) -> None:
        """Without a cache, an unusable cloud asks for an online update."""
        for mode in ("down", "503"):
            with self.subTest(mode=mode):
                self.cloud.mode = mode
                with self.assertRaises(NetworkOnlineUpdateNeededError):
                    await self.casa().connect(ADDRESS, PASSWORD)

    async def test_rejected_password_is_an_authentication_error(self) -> None:
        """Only a 401 login is reported as a rejected password."""
        with self.assertRaises(AuthenticationError) as ctx:
            await self.casa().connect(ADDRESS, "wrong")
        self.assertEqual(ctx.exception.status_code, 401)

    async def test_refresh_caches_a_newer_configuration(self) -> None:
        """A refresh caches a newer revision for the next connect only."""
        casa = self.casa()
        await casa.connect(ADDRESS, PASSWORD, preferCache=True)
        self.assertFalse(await casa.refreshNetwork(PASSWORD))

        self.cloud.network = _network(2, ["Lamp", "New lamp"])
        self.assertTrue(await casa.refreshNetwork(PASSWORD))
        # The units in use stay untouched until the next connect.
        self.assertEqual([u.name for u in casa.units], ["Lamp"])
        self.assertEqual(casa.networkRevision, 1)

        self.cloud.mode = "down"
        reconnected = self.casa()
        await reconnected.connect(ADDRESS, PASSWORD, preferCache=True)
        self.assertEqual([u.name for u in reconnected.units], ["Lamp", "New lamp"])
        self.assertEqual(reconnected.networkRevision, 2)

    async def test_refresh_reports_an_unavailable_cloud(self) -> None:
        """A refresh during an outage carries the http status."""
        casa = self.casa()
        await casa.connect(ADDRESS, PASSWORD, preferCache=True)
        self.cloud.mode = "503"
        self.cloud.network = _network(2, ["Lamp", "New lamp"])
        with self.assertRaises(CloudUnavailableError) as ctx:
            await casa.refreshNetwork(PASSWORD)
        self.assertEqual(ctx.exception.status_code, 503)

    async def test_gone_session_keeps_the_configuration(self) -> None:
        """A revoked session keeps the cached configuration and keys."""
        casa = self.casa()
        await casa.connect(ADDRESS, PASSWORD)
        self.cloud.mode = "410"
        with self.assertRaises(AuthenticationError) as ctx:
            await casa.refreshNetwork(PASSWORD)
        self.assertEqual(ctx.exception.status_code, 410)
        self.assertFalse((self.cacheDir / UUID / "session.pck").exists())

        self.cloud.mode = "down"
        offline = self.casa()
        await offline.connect(ADDRESS, PASSWORD, forceOffline=True)
        self.assertEqual([u.name for u in offline.units], ["Lamp"])

    async def test_expired_unit_type_is_kept_while_the_cloud_is_down(self) -> None:
        """Expired unit types stay in use offline."""
        await self.casa().connect(ADDRESS, PASSWORD)
        typesFile = self.cacheDir / UUID / "types.pck"
        types = pickle.loads(typesFile.read_bytes())
        unitType, _ = types[FIXTURE["id"]]
        types[FIXTURE["id"]] = (unitType, datetime.utcnow() - timedelta(days=1))
        typesFile.write_bytes(pickle.dumps(types))

        self.cloud.mode = "down"
        casa = self.casa()
        await casa.connect(ADDRESS, PASSWORD)
        self.assertEqual(casa.units[0].unitType.model, "Synthetic dimmer")

    async def test_backup_restores_a_network_without_the_cloud(self) -> None:
        """A backup restores units, fixtures and keys on a fresh cache."""
        casa = self.casa()
        await casa.connect(ADDRESS, PASSWORD)
        backup = json.loads(json.dumps(await casa.exportOfflineBackup()))

        self.cloud.mode = "down"
        newInstall = Path(self._tmp.name) / "new-install" / "casambi"
        restored = self.casa(newInstall)
        self.assertEqual(await restored.importOfflineBackup(backup), ADDRESS)
        await restored.connect(ADDRESS, "", forceOffline=True)

        self.assertEqual(restored.networkId, NETWORK_ID)
        self.assertEqual([u.name for u in restored.units], ["Lamp"])
        self.assertEqual(restored.units[0].unitType.eventProfile, FIXTURE)
        key = restored._casaNetwork.keyStore.getKey()  # type: ignore[union-attr]
        self.assertEqual(key.key, bytes(16))

    async def test_restore_drops_the_cached_session(self) -> None:
        """A restored backup never reuses the old cloud session."""
        casa = self.casa()
        await casa.connect(ADDRESS, PASSWORD)
        backup = await casa.exportOfflineBackup()
        await casa.importOfflineBackup(backup)
        self.assertFalse((self.cacheDir / UUID / "session.pck").exists())

    async def test_invalid_backups_are_rejected(self) -> None:
        """Invalid backups raise OfflineBackupError before touching the cache."""
        casa = self.casa()
        await casa.connect(ADDRESS, PASSWORD)
        valid = await casa.exportOfflineBackup()
        invalid = {
            "not an object": [],
            "foreign format": {**valid, "format": "casambi-bt-offline-backup"},
            "newer version": {**valid, "version": 2},
            "bad address": {**valid, "address": "not-a-mac"},
            "path in network id": {**valid, "networkId": "../x"},
            "no configuration": {k: v for k, v in valid.items() if k != "network"},
            "malformed fixture": {**valid, "unitTypes": [{"id": 1}]},
        }
        for name, backup in invalid.items():
            with self.subTest(name), self.assertRaises(OfflineBackupError):
                await casa.importOfflineBackup(backup)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
