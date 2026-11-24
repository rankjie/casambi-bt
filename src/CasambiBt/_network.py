import json
import logging
import pickle
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Final, cast

import httpx
from httpx import AsyncClient, RequestError

from ._cache import Cache
from ._constants import DEVICE_NAME
from ._keystore import KeyStore
from ._unit import Group, Scene, Unit, UnitControl, UnitControlType, UnitType
from .errors import (
    AuthenticationError,
    CloudUnavailableError,
    NetworkNotFoundError,
    NetworkOnlineUpdateNeededError,
)

SESSION_CACHE_FILE: Final = "session.pck"
TYPES_CACHE_FILE: Final = "types.pck"
NETWORK_ID_FILE: Final = "networkid"

# Unit types are refetched after this time when the cloud is used. An expired
# type stays in use while the cloud can't be reached.
TYPE_CACHE_DURATION: Final = timedelta(days=28)

# Login answers that reject the credentials. Every other error of the cloud
# (maintenance, rate limits, ...) says nothing about the password.
AUTH_REJECTED_STATUSES: Final = frozenset({httpx.codes.UNAUTHORIZED})


@dataclass()
class _NetworkSession:
    session: str
    network: str
    manager: bool
    keyID: int
    expires: datetime

    role: int = 3  # TODO: Support other role types?

    def expired(self) -> bool:
        return datetime.utcnow() > self.expires


class Network:
    def __init__(self, uuid: str, httpClient: AsyncClient, cache: Cache) -> None:
        self._session: _NetworkSession | None = None

        self._networkName: str | None = None
        self._networkRevision: int | None = None
        self._protocolVersion: int = -1
        self._grade: int | None = None
        # Classic networks do not have a `keyStore`; instead they expose visitor/manager keys.
        # Ground truth: casambi-android `D1.Z0` exports `visitorKey`/`managerKey`.
        self._classicVisitorKey: bytes | None = None
        self._classicManagerKey: bytes | None = None
        self._rawNetworkData: dict | None = None

        self._unitTypes: dict[int, tuple[UnitType | None, datetime]] = {}
        self.units: list[Unit] = []
        self.groups: list[Group] = []
        self.scenes: list[Scene] = []

        self._logger = logging.getLogger(__name__)
        # TODO: Create LoggingAdapter to prepend uuid.

        self._id: str | None = None
        self._uuid = uuid
        self._httpClient = httpClient

        self._cache = cache

        # Android sends "fb:<FCM_token>" — we have no push token, use empty string
        # to match the field type without leaking platform info.
        self._token: str = ""
        # Android: "{flavor}/{version} {manufacturer}_{model}/{os_release}"
        _app_version = random.choice((
            "3.19.0", "3.18.2", "3.18.1", "3.18.0",
            "3.17.4", "3.17.3", "3.17.2", "3.17.1", "3.17.0",
            "3.16.5", "3.16.4", "3.16.3", "3.16.1", "3.16.0",
            "3.15.3", "3.15.2", "3.15.1", "3.15.0",
            "3.14.2", "3.14.1", "3.14.0",
            "3.13.2", "3.13.1", "3.13.0",
            "3.12.4", "3.12.3", "3.12.1", "3.12.0",
            "3.11.2", "3.11.1",
        ))
        _device = random.choice((
            # Samsung Galaxy S series
            "samsung_SM-S928B/15",   # S24 Ultra
            "samsung_SM-S926B/15",   # S24+
            "samsung_SM-S921B/15",   # S24
            "samsung_SM-S918B/14",   # S23 Ultra
            "samsung_SM-S916B/14",   # S23+
            "samsung_SM-S911B/14",   # S23
            "samsung_SM-S908B/14",   # S22 Ultra
            "samsung_SM-S906B/14",   # S22+
            "samsung_SM-S901B/14",   # S22
            "samsung_SM-G998B/13",   # S21 Ultra
            "samsung_SM-G996B/13",   # S21+
            "samsung_SM-G991B/13",   # S21
            # Samsung Galaxy A series
            "samsung_SM-A556B/14",   # A55
            "samsung_SM-A546B/14",   # A54
            "samsung_SM-A346B/14",   # A34
            "samsung_SM-A536B/13",   # A53
            # Google Pixel
            "Google_Pixel 8 Pro/14",
            "Google_Pixel 8/14",
            "Google_Pixel 7 Pro/14",
            "Google_Pixel 7/14",
            # OnePlus
            "OnePlus_IN2023/14",     # 12
            "OnePlus_CPH2449/14",    # 11
        ))
        self._clientInfo: str = f"Casambi/{_app_version} {_device}"

    async def load(self) -> None:
        self._keystore = KeyStore(self._cache)
        await self._keystore.load()

        await self._loadSession()
        await self._loadTypeCache()

    async def _loadSession(self) -> None:
        self._logger.debug("Loading session...")
        async with self._cache as cachePath:
            if await (cachePath / SESSION_CACHE_FILE).exists():
                sessionData = await (cachePath / SESSION_CACHE_FILE).read_bytes()
                self._session = pickle.loads(sessionData)
                self._logger.info("Session loaded.")

    async def _saveSesion(self) -> None:
        self._logger.debug("Saving session...")
        async with self._cache as cachePath:
            sessionData = pickle.dumps(self._session)
            await (cachePath / SESSION_CACHE_FILE).write_bytes(sessionData)

    async def _loadTypeCache(self) -> None:
        self._logger.debug("Loading unit type cache...")
        async with self._cache as cachePath:
            if await (cachePath / TYPES_CACHE_FILE).exists():
                typeData = await (cachePath / TYPES_CACHE_FILE).read_bytes()
                self._unitTypes = pickle.loads(typeData)
                self._logger.info("Unit type cache loaded.")

    async def _saveTypeCache(self) -> None:
        self._logger.debug("Saving type cache...")
        async with self._cache as cachePath:
            typeData = pickle.dumps(self._unitTypes)
            await (cachePath / TYPES_CACHE_FILE).write_bytes(typeData)

    async def _readCachedNetworkId(self) -> None:
        async with self._cache as cachePath:
            networkCacheFile = cachePath / NETWORK_ID_FILE
            if await networkCacheFile.exists():
                self._id = (await networkCacheFile.read_text()).strip() or None

    async def _readCachedNetwork(self) -> dict[str, Any] | None:
        """Return the cached network configuration or None if there is none."""
        if not self._id:
            return None
        async with self._cache as cachePath:
            cachedNetworkPath = cachePath / f"{self._id}.json"
            if not await cachedNetworkPath.exists():
                return None
            try:
                network = json.loads(await cachedNetworkPath.read_bytes())
                int(network["network"]["revision"])
            except (ValueError, KeyError, TypeError):
                self._logger.warning("Cached network is unreadable.", exc_info=True)
                return None
            return cast(dict[str, Any], network)

    async def hasCache(self) -> bool:
        """Return True if the network configuration can be loaded without the cloud."""
        await self._readCachedNetworkId()
        return await self._readCachedNetwork() is not None

    async def getNetworkId(self, forceOffline: bool = False) -> None:
        self._logger.info("Getting network id...")

        await self._readCachedNetworkId()

        if forceOffline:
            if not self._id:
                raise NetworkOnlineUpdateNeededError("Network isn't cached.")
            return

        getNetworkIdUrl = f"https://api.casambi.com/network/uuid/{self._uuid}"
        try:
            res = await self._httpClient.get(getNetworkIdUrl)
            new_id = (
                str(res.json()["id"]) if res.status_code == httpx.codes.OK else None
            )
        except (RequestError, ValueError, KeyError, TypeError) as err:
            if not self._id:
                raise NetworkOnlineUpdateNeededError(
                    "Casambi cloud not usable and network id isn't cached."
                ) from err
            self._logger.warning(
                "Failed to fetch network id. Continuing with cache.", exc_info=True
            )
            return

        if new_id is None:
            if self._id:
                # The id of a network never changes, the cached one is fine.
                self._logger.warning(
                    "Getting network id returned status %i. Continuing with cache.",
                    res.status_code,
                )
                return
            if res.status_code == httpx.codes.NOT_FOUND:
                raise NetworkNotFoundError(
                    "API failed to find network. Is your network configured correctly?"
                )
            raise CloudUnavailableError(
                f"Getting network id returned unexpected status {res.status_code}",
                res.status_code,
            )

        if self._id != new_id:
            self._logger.info(f"Network id changed from {self._id} to {new_id}.")
            async with self._cache as cachePath:
                await (cachePath / NETWORK_ID_FILE).write_text(new_id)
            self._id = new_id
        self._logger.info(f"Got network id {self._id}.")

    def authenticated(self) -> bool:
        if not self._session:
            return False
        return not self._session.expired()

    def isManager(self) -> bool:
        """Whether the current cloud session has manager privileges."""
        return bool(self._session and self._session.manager)

    @property
    def keyStore(self) -> KeyStore:
        return self._keystore

    @property
    def protocolVersion(self) -> int:
        return self._protocolVersion

    @property
    def revision(self) -> int | None:
        """Revision of the network configuration in use."""
        return self._networkRevision

    @property
    def grade(self) -> int | None:
        """Network grade (aka firmware grade) if present in the cloud profile."""
        return self._grade

    def classicVisitorKey(self) -> bytes | None:
        return self._classicVisitorKey

    def classicManagerKey(self) -> bytes | None:
        return self._classicManagerKey

    def classicBestKey(self) -> bytes | None:
        # Prefer manager key if present, otherwise visitor key.
        return self._classicManagerKey or self._classicVisitorKey

    def hasClassicKeys(self) -> bool:
        return bool(self._classicVisitorKey or self._classicManagerKey)

    @property
    def rawNetworkData(self) -> dict | None:
        return self._rawNetworkData

    async def logIn(self, password: str, forceOffline: bool = False) -> None:
        """Log in to the cloud unless a valid session exists.

        :raises AuthenticationError: The cloud rejected the password.
        :raises CloudUnavailableError: The cloud can't be used at the moment.
        """
        await self.getNetworkId(forceOffline)

        # No need to be authenticated if we try to be offline anyway.
        if self.authenticated() or forceOffline:
            return

        self._logger.info("Logging in to network...")
        getSessionUrl = f"https://api.casambi.com/network/{self._id}/session"

        try:
            res = await self._httpClient.post(
                getSessionUrl,
                json={
                    "token": self._token,
                    "password": password,
                    "deviceName": DEVICE_NAME,
                },
            )
        except RequestError as err:
            raise CloudUnavailableError("Casambi cloud not reachable.") from err

        if res.status_code in AUTH_REJECTED_STATUSES:
            raise AuthenticationError(
                f"Login failed: {res.status_code}", status_code=res.status_code
            )
        if res.status_code != httpx.codes.OK:
            raise CloudUnavailableError(
                f"Login failed: {res.status_code}", res.status_code
            )

        try:
            sessionJson = res.json()
            sessionJson["expires"] = datetime.utcfromtimestamp(
                sessionJson["expires"] / 1000
            )
            self._session = _NetworkSession(**sessionJson)
        except (ValueError, KeyError, TypeError) as err:
            raise CloudUnavailableError("Malformed login response.") from err
        self._logger.info("Login sucessful.")
        await self._saveSesion()

    async def _dropSession(self) -> None:
        self._session = None
        async with self._cache as cachePath:
            await (cachePath / SESSION_CACHE_FILE).unlink(missing_ok=True)

    async def _fetchNetwork(self, revision: int) -> dict[str, Any] | None:
        """Fetch the network configuration if the cloud has a newer revision.

        A newer configuration is written to the cache.

        :return: The new configuration or None if the given revision is current.
        :raises AuthenticationError: Not logged in or the session was revoked.
        :raises CloudUnavailableError: The cloud can't be used at the moment.
        """
        if not self.authenticated():
            raise AuthenticationError("Not authenticated!")
        assert self._session is not None

        getNetworkUrl = f"https://api.casambi.com/network/{self._id}/"
        payload: dict[str, Any] = {
            "formatVersion": 1,
            "deviceName": DEVICE_NAME,
            "revision": revision,
        }
        try:
            # **SECURITY**: Do not set session header for client! This could leak the session with external clients.
            res = await self._httpClient.put(
                getNetworkUrl,
                json=payload,
                headers={"X-Casambi-Session": self._session.session},
            )
            if res.status_code == httpx.codes.BAD_REQUEST:
                # Some backend variants may reject the minimal update payload.
                # Retry once with Android-like fields (token/clientInfo).
                self._logger.warning(
                    "[CASAMBI_CLOUD_UPDATE_RETRY] status=400 retry_with_token_clientInfo=true"
                )
                payload["token"] = self._token
                payload["clientInfo"] = self._clientInfo
                res = await self._httpClient.put(
                    getNetworkUrl,
                    json=payload,
                    headers={"X-Casambi-Session": self._session.session},
                )
        except RequestError as err:
            raise CloudUnavailableError("Casambi cloud not reachable.") from err

        if res.status_code == httpx.codes.GONE:
            # Happens when the password changes. Only the session is invalid:
            # keep the configuration and its keys so the network keeps working
            # offline until the user logs in again.
            self._logger.error("API reports that the session is gone.")
            await self._dropSession()
            raise AuthenticationError(
                "Session is no longer valid.", status_code=res.status_code
            )
        if res.status_code != httpx.codes.OK:
            raise CloudUnavailableError(
                f"Network update failed: {res.status_code}", res.status_code
            )

        try:
            updateResult = cast(dict[str, Any], res.json())
            if updateResult["status"] == "UPTODATE":
                return None
            int(updateResult["network"]["revision"])
        except (ValueError, KeyError, TypeError) as err:
            raise CloudUnavailableError("Malformed network response.") from err

        async with self._cache as cachePath:
            await (cachePath / f"{self._id}.json").write_bytes(res.content)
        return updateResult

    async def update(self, forceOffline: bool = False) -> None:
        """Load the network configuration, from the cloud if possible.

        Cloud errors fall back to the cached configuration.

        :raises AuthenticationError: Not logged in or the session was revoked.
        :raises NetworkOnlineUpdateNeededError: The network isn't cached and
            the cloud can't be used.
        """
        self._logger.info("Updating network...")
        if not self.authenticated() and not forceOffline:
            raise AuthenticationError("Not authenticated!")

        if self._id is None:
            # Only reachable offline: the cloud didn't provide the id either.
            raise NetworkOnlineUpdateNeededError("Network isn't cached.")

        network = await self._readCachedNetwork()
        if network is not None:
            self._networkRevision = int(network["network"]["revision"])
            self._logger.info(
                f"Loaded cached network. Revision: {self._networkRevision}"
            )
        elif forceOffline:
            raise NetworkOnlineUpdateNeededError("Network isn't cached.")
        else:
            self._networkRevision = 0

        if not forceOffline:
            try:
                fresh = await self._fetchNetwork(self._networkRevision or 0)
            except CloudUnavailableError as err:
                if network is None:
                    raise NetworkOnlineUpdateNeededError(
                        "Network isn't cached and the cloud can't be used."
                    ) from err
                self._logger.warning(
                    "[CASAMBI_CLOUD_UPDATE_FAILED] %s cached_revision=%s continuing_offline=true",
                    err,
                    self._networkRevision,
                )
            else:
                if fresh is not None:
                    network = fresh
                    self._networkRevision = int(fresh["network"]["revision"])
                    self._logger.info(
                        f"Fetched updated network with revision {self._networkRevision}"
                    )

        assert network is not None
        self._rawNetworkData = network

        # Prase general information
        self._networkName = network["network"]["name"]
        self._protocolVersion = network["network"]["protocolVersion"]
        grade = network["network"].get("grade")
        try:
            self._grade = int(grade) if grade is not None else None
        except (TypeError, ValueError):
            self._grade = None

        # Parse keys if there are any. Otherwise the network is probably a classic network.
        if "keyStore" in network["network"]:
            keys = network["network"]["keyStore"]["keys"]
            for k in keys:
                await self._keystore.addKey(k)
            # Evolution network: classic keys not used
            self._classicVisitorKey = None
            self._classicManagerKey = None
        else:
            # Classic network: parse visitorKey / managerKey (hex strings).
            # Ground truth: casambi-android `D1.Z0` exports these fields.
            visitor_hex = network["network"].get("visitorKey")
            manager_hex = network["network"].get("managerKey")

            def _parse_hex_key(v: object) -> bytes | None:
                if not isinstance(v, str):
                    return None
                v = v.strip()
                if not v:
                    return None
                try:
                    return bytes.fromhex(v)
                except ValueError:
                    return None

            self._classicVisitorKey = _parse_hex_key(visitor_hex)
            self._classicManagerKey = _parse_hex_key(manager_hex)
            if not (self._classicVisitorKey or self._classicManagerKey):
                # Android still sends Classic frames even when keys are null (signature bytes remain zeros).
                # We need this as a loud hint for testers when Classic control doesn't work yet.
                self._logger.warning(
                    "[CASAMBI_CLASSIC_KEYS_MISSING] visitorKey=false managerKey=false"
                )
            else:
                self._logger.info(
                    "Classic keys present: visitor=%s manager=%s",
                    bool(self._classicVisitorKey),
                    bool(self._classicManagerKey),
                )

        # Parse units
        self.units = []
        units = network["network"]["units"]
        units_with_security_key = 0
        for u in units:
            uType = await self._fetchUnitInfo(u["type"], forceOffline)
            if uType is None:
                self._logger.info(
                    "Failed to fetch type for unit %i. Skipping.", u["type"]
                )
                continue

            security_key: bytes | None = None
            sec_hex = u.get("securityKey")
            if isinstance(sec_hex, str):
                sec_hex = sec_hex.strip()
                if sec_hex:
                    try:
                        security_key = bytes.fromhex(sec_hex)
                    except ValueError:
                        self._logger.debug(
                            "Invalid unit securityKey hex for unit %s (len=%d).",
                            u.get("deviceID"),
                            len(sec_hex),
                        )
            if security_key is not None:
                units_with_security_key += 1

            uObj = Unit(
                u["type"],
                u["deviceID"],
                u["uuid"],
                u["address"],
                u["name"],
                str(u["firmware"]),
                uType,
                securityKey=security_key,
                networkProtocolVersion=self._protocolVersion,
                networkGrade=self._grade,
            )
            self.units.append(uObj)

        # One compact profile line to help interpret mixed/legacy networks from tester logs.
        # Keep EVO networks at INFO to avoid noisy HA warnings; elevate legacy (<10) to WARNING.
        level = logging.WARNING if self._protocolVersion < 10 else logging.INFO
        self._logger.log(
            level,
            "[CASAMBI_NETWORK_PROFILE] uuid=%s id=%s protocolVersion=%s grade=%s units=%d units_with_securityKey=%d keyStore=%s",
            self._uuid,
            self._id,
            self._protocolVersion,
            self._grade,
            len(self.units),
            units_with_security_key,
            "keyStore" in network["network"],
        )

        # Parse cells
        self.groups = []
        cells = network["network"]["grid"]["cells"]
        for c in cells:
            # Only one type at top level is currently supported
            if c["type"] != 2:
                continue

            # Parse group members
            group_units = []
            # We assume no nested groups here
            for subC in c["cells"]:
                # Ignore everyting that isn't a unit
                if subC["type"] != 1:
                    continue

                unitMatch = list(
                    filter(lambda u: u.deviceId == subC["unit"], self.units)
                )
                if len(unitMatch) != 1:
                    self._logger.warning(
                        f"Incositent unit reference to {subC['unit']} in group {c['groupID']}. Got {len(unitMatch)} matches."
                    )
                    continue
                group_units.append(unitMatch[0])

            gObj = Group(c["groupID"], c["name"], group_units)
            self.groups.append(gObj)

        # Parse scenes
        self.scenes = []
        scenes = network["network"]["scenes"]
        for s in scenes:
            sObj = Scene(s["sceneID"], s["name"])
            self.scenes.append(sObj)

        # TODO: Parse more stuff

        await self._saveTypeCache()

        self._logger.info("Network updated.")

    async def fetchUpdate(self) -> bool:
        """Download a newer network configuration into the cache.

        The configuration in use (units, groups, scenes) is left untouched so
        live objects stay valid; the next connect applies it. The unit types of
        the new configuration are fetched too so it also works offline.

        :return: True if the cloud had a newer configuration.
        :raises AuthenticationError: Not logged in or the session was revoked.
        :raises CloudUnavailableError: The cloud can't be used at the moment.
        """
        fresh = await self._fetchNetwork(self._networkRevision or 0)
        if fresh is None:
            return False
        for u in fresh["network"].get("units", []):
            if isinstance(u, dict) and isinstance(u.get("type"), int):
                await self._fetchUnitInfo(u["type"])
        await self._saveTypeCache()
        return True

    async def _fetchUnitInfo(
        self, id: int, forceOffline: bool = False
    ) -> UnitType | None:
        """Return the type of a unit.

        A cached type is used until it expires. An expired type, or one cached
        before the fixture JSON was kept, is refetched but stays in use if the
        cloud can't be used. Failures are not cached so the next connect tries
        again.
        """
        cachedType: UnitType | None = None
        if id in self._unitTypes:
            cachedType, cacheExpiry = self._unitTypes[id]
            if (
                cachedType is not None
                and cachedType.eventProfile is not None
                and cacheExpiry >= datetime.utcnow()
            ):
                return cachedType

        if forceOffline:
            return cachedType

        self._logger.info(f"Fetching unit type for id {id}...")
        getUnitInfoUrl = f"https://api.casambi.com/fixture/{id}"
        try:
            res = await self._httpClient.get(getUnitInfoUrl)
            if res.status_code != httpx.codes.OK:
                self._logger.warning(
                    "Getting unit info for %i returned %i.", id, res.status_code
                )
                return cachedType
            unitTypeObj = parseUnitType(res.json())
        except (RequestError, ValueError, KeyError, TypeError):
            self._logger.warning("Failed to fetch unit info for %i.", id, exc_info=True)
            return cachedType

        self._unitTypes[unitTypeObj.id] = (
            unitTypeObj,
            datetime.utcnow() + TYPE_CACHE_DURATION,
        )
        self._logger.info("Sucessfully fetched unit type.")
        return unitTypeObj

    def unitTypes(self) -> dict[int, UnitType]:
        """Return the known unit types."""
        return {k: v for k, (v, _) in self._unitTypes.items() if v is not None}

    async def storeUnitTypes(self, types: list[UnitType]) -> None:
        """Store unit types in the cache, e.g. from an offline backup."""
        for t in types:
            self._unitTypes[t.id] = (t, datetime.utcnow() + TYPE_CACHE_DURATION)
        await self._saveTypeCache()

    async def disconnect(self) -> None:
        return None


def parseUnitType(unitTypeJson: dict[str, Any]) -> UnitType:
    """Parse a fixture as returned by the cloud. The JSON is kept as event profile."""
    logger = logging.getLogger(__name__)
    controls = []
    for controlJson in unitTypeJson["controls"]:
        typeStr = str(controlJson["type"]).upper()
        try:
            type = UnitControlType[typeStr]
        except KeyError:
            logger.warning(
                "Unsupported control mode %s in fixture %s.",
                typeStr,
                unitTypeJson.get("id"),
            )
            type = UnitControlType.UNKOWN

        controls.append(
            UnitControl(
                type,
                controlJson["offset"],
                controlJson["length"],
                controlJson["default"],
                controlJson["readonly"],
                controlJson.get("min", None),
                controlJson.get("max", None),
            )
        )

    return UnitType(
        unitTypeJson["id"],
        unitTypeJson["model"],
        unitTypeJson["vendor"],
        unitTypeJson["mode"],
        unitTypeJson["stateLength"],
        controls,
        unitTypeJson,
    )
