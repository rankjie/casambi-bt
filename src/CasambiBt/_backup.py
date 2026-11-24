"""Offline backups of a network.

A backup holds everything needed to connect to a network without the Casambi
cloud: the network configuration as delivered by the cloud (including the keys
of the network) and the fixtures of its unit types. Restoring it fills the
cache so that a connect works offline.

The backup contains the keys of the network. Treat it like a password.
"""

import json
import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

from ._cache import Cache
from ._constants import normalizeAddress
from .errors import OfflineBackupError

if TYPE_CHECKING:
    from ._network import Network

_LOGGER = logging.getLogger(__name__)

BACKUP_FORMAT: Final = "casambi-bt-revamped-offline-backup"
BACKUP_VERSION: Final = 1


async def createBackup(network: "Network") -> dict[str, Any]:
    """Create an offline backup of a loaded network.

    :raises OfflineBackupError: The configuration or a unit type isn't cached.
    """
    configuration = await network._readCachedNetwork()  # noqa: SLF001
    if configuration is None:
        raise OfflineBackupError("The network configuration isn't cached.")

    knownTypes = network.unitTypes()
    fixtures: list[dict[str, Any]] = []
    missing: list[int] = []
    for typeId in sorted({u.unitType.id for u in network.units}):
        unitType = knownTypes.get(typeId)
        # The fixture JSON holds the switch event profile, a backup without it
        # would silently lose switch events after a restore.
        if unitType is None or unitType.eventProfile is None:
            missing.append(typeId)
        else:
            fixtures.append(unitType.eventProfile)
    if missing:
        raise OfflineBackupError(
            f"The unit types {missing} aren't cached. Connect once with the cloud."
        )

    return {
        "format": BACKUP_FORMAT,
        "version": BACKUP_VERSION,
        "created": datetime.now(UTC).isoformat(),
        "address": normalizeAddress(network._uuid),  # noqa: SLF001
        "networkId": network._id,  # noqa: SLF001
        "network": configuration,
        "unitTypes": fixtures,
    }


async def restoreBackup(cache: Cache, backup: Mapping[str, Any]) -> str:
    """Write a backup into the cache and return the address of the network.

    The cached session is dropped: it belongs to the password of the network at
    the time of the old cache, not to the backup.

    :raises OfflineBackupError: The backup is invalid.
    """
    # Late import to avoid a cycle with the network module.
    from ._network import NETWORK_ID_FILE, SESSION_CACHE_FILE, Network, parseUnitType

    if not isinstance(backup, Mapping):
        raise OfflineBackupError("The backup isn't an object.")
    if backup.get("format") != BACKUP_FORMAT:
        raise OfflineBackupError("This isn't a casambi-bt-revamped offline backup.")
    if backup.get("version") != BACKUP_VERSION:
        raise OfflineBackupError(
            f"Unsupported backup version {backup.get('version')!r}."
        )
    try:
        address = normalizeAddress(str(backup["address"]))
        networkId = str(backup["networkId"])
        if not networkId or "/" in networkId or networkId.startswith("."):
            raise ValueError("Invalid network id.")
        configuration = dict(backup["network"])
        netJson = configuration["network"]
        int(netJson["revision"])
        str(netJson["name"])
        int(netJson["protocolVersion"])
        unitTypeIds = {int(u["type"]) for u in netJson["units"]}
        unitTypes = [parseUnitType(dict(t)) for t in backup["unitTypes"]]
    except (KeyError, TypeError, ValueError) as err:
        raise OfflineBackupError("The backup is incomplete or malformed.") from err
    missing = unitTypeIds - {t.id for t in unitTypes}
    if missing:
        # Units of these types were already skipped when the backup was made.
        _LOGGER.warning("The backup lacks the unit types %s.", sorted(missing))

    uuid = address.replace(":", "").lower()
    restoreCache = Cache(cache._cachePath)  # noqa: SLF001
    await restoreCache.setUuid(uuid)
    async with restoreCache as cachePath:
        await (cachePath / NETWORK_ID_FILE).write_text(networkId)
        await (cachePath / f"{networkId}.json").write_text(json.dumps(configuration))
        await (cachePath / SESSION_CACHE_FILE).unlink(missing_ok=True)

    network = Network(uuid, None, restoreCache)  # type: ignore[arg-type]
    await network.load()
    await network.storeUnitTypes(unitTypes)

    _LOGGER.info(
        "Restored offline backup of network %s with %i unit types.",
        address,
        len(unitTypes),
    )
    return address
