import asyncio
import inspect
import logging
import os
import platform
import struct
import time
from binascii import b2a_hex as b2a
from collections.abc import Callable
from enum import Enum, IntEnum, auto, unique
from hashlib import sha256
from typing import Any, Final

from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.client import BLEDevice
from bleak.exc import BleakError
from bleak_retry_connector import (
    BleakNotFoundError,
    close_stale_connections,
    establish_connection,
    get_device,
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

from ._constants import CASA_AUTH_CHAR_UUID, ConnectionState
from ._constants import (
    CASA_CLASSIC_CA53_CHAR_UUID,
    CASA_CLASSIC_CONFORMANT_CA51_CHAR_UUID,
    CASA_CLASSIC_CONFORMANT_CA53_CHAR_UUID,
    CASA_CLASSIC_DATA_CHAR_UUID,
    CASA_CLASSIC_HASH_CHAR_UUID,
)
from ._classic_crypto import classic_cmac_prefix
from ._encryption import Encryptor
from ._network import Network
from ._switch_events import SwitchEventStreamDecoder

# We need to move these imports here to prevent a cycle.
from .errors import (  # noqa: E402
    BluetoothError,
    ConnectionStateError,
    ClassicHandshakeError,
    ClassicKeysMissingError,
    NetworkNotFoundError,
    ProtocolError,
    UnsupportedProtocolVersion,
)


@unique
class IncommingPacketType(IntEnum):
    UnitState = 6
    SwitchEvent = 7
    NetworkConfig = 9


class ProtocolMode(Enum):
    EVO = auto()
    CLASSIC = auto()


class _LogBurstLimiter:
    """Simple in-process log rate limiter (per key).

    Home Assistant warns if a logger emits too many messages. We keep some high-signal
    WARNING logs for Classic reverse engineering but avoid spamming.
    """

    def __init__(self) -> None:
        self._state: dict[str, tuple[float, int]] = {}

    def allow(self, key: str, *, burst: int, window_s: float) -> bool:
        now = time.monotonic()
        start, count = self._state.get(key, (now, 0))
        if (now - start) > window_s:
            start, count = now, 0
        if count >= burst:
            self._state[key] = (start, count)
            return False
        self._state[key] = (start, count + 1)
        return True


MIN_VERSION: Final[int] = 10
MAX_VERSION: Final[int] = 11


class CasambiClient:
    def __init__(
        self,
        address_or_device: str | BLEDevice,
        dataCallback: Callable[[IncommingPacketType, dict[str, Any]], None],
        disonnectedCallback: Callable[[], None],
        network: Network,
    ) -> None:
        self._gattClient: BleakClient = None  # type: ignore[assignment]
        self._notifySignal = asyncio.Event()
        self._network = network

        self._mtu: int
        self._unitId: int
        self._flags: int
        self._nonce: bytes
        self._key: bytearray

        self._encryptor: Encryptor

        self._outPacketCount = 0
        self._inPacketCount = 0

        self._callbackQueue: asyncio.Queue[tuple[BleakGATTCharacteristic, bytes]]
        self._callbackTask: asyncio.Task[None] | None = None

        self._address_or_devive = address_or_device
        self.address = (
            address_or_device.address
            if isinstance(address_or_device, BLEDevice)
            else address_or_device
        )
        self._logger = logging.getLogger(__name__)
        self._switchDecoder = SwitchEventStreamDecoder(self._logger)
        self._connectionState: ConnectionState = ConnectionState.NONE
        self._dataCallback = dataCallback
        self._disconnectedCallback = disonnectedCallback
        self._activityLock = asyncio.Lock()

        # Determined at runtime by inspecting GATT services/characteristics.
        self._protocolMode: ProtocolMode | None = None
        self._dataCharUuid: str | None = None
        # EVO only: protocolVersion from the device-provided NodeInfo (byte1).
        self._deviceProtocolVersion: int | None = None

        # Classic protocol state
        self._classicConnHash8: bytes | None = None
        self._classicTxSeq: int = 0  # 16-bit sequence number (big endian on the wire)
        self._classicCmdDiv: int = 0  # 8-bit per-command divider/id (matches u1.C1751c.b0)
        # Classic header framing mode:
        # - "conformant": [auth][sig][seq16][payload]
        # - "legacy":     [sig][payload]
        # Ground truth: casambi-android `t1.P.n(...)` and `t1.P.o(...)`.
        self._classicHeaderMode: str | None = None  # "conformant" | "legacy"
        # Classic transport diagnostics / channel selection.
        self._classicTxCharUuid: str | None = None
        self._classicNotifyCharUuids: set[str] = set()
        self._classicHashSource: str | None = None  # "ca51" | "ca52_0001" | None
        self._classicFirstRxTs: float | None = None
        self._classicNoRxTask: asyncio.Task[None] | None = None

        # Rate limit WARNING logs (especially Classic RX) to keep HA usable.
        self._logLimiter = _LogBurstLimiter()
        self._classicRxFrames = 0
        self._classicRxVerified = 0
        self._classicRxUnverifiable = 0
        self._classicRxParseFail = 0
        self._classicRxType6 = 0
        self._classicRxType7 = 0
        self._classicRxType9 = 0
        self._classicRxCmdStream = 0
        self._classicRxUnknown = 0
        self._classicRxClassicStates = 0
        # Per-kind sample counters to ensure we emit at least a few examples for reverse engineering.
        self._classicRxKindSamples: dict[str, int] = {}
        self._classicRxLastStatsTs = time.monotonic()

        # Classic diagnostic packet history (for dump_classic_diagnostics service)
        self._classicTxHistory: list[dict[str, Any]] = []
        self._classicRxHistory: list[dict[str, Any]] = []
        self._classicDiagMaxHistory = 50  # Keep last 50 TX and RX packets

    @property
    def protocolMode(self) -> ProtocolMode | None:
        return self._protocolMode

    def _checkProtocolVersion(self, version: int, *, source: str = "unknown") -> None:
        if version < MIN_VERSION:
            # Legacy protocol versions are intentionally allowed. We keep this check as a warning
            # because packet layouts/handshakes may differ and we want actionable tester logs.
            msg = (
                f"Legacy protocol version detected ({source}={version}). "
                f"Versions < {MIN_VERSION} are not fully verified; attempting to continue."
            )
            self._logger.warning(msg)
            return
        if version > MAX_VERSION:
            self._logger.warning(
                "Version too new (%s=%i). Highest supported version is %i. Continue at your own risk.",
                source,
                version,
                MAX_VERSION,
            )

    def _checkState(self, desired: ConnectionState) -> None:
        if self._connectionState != desired:
            raise ConnectionStateError(desired, self._connectionState)

    async def connect(self) -> None:
        self._checkState(ConnectionState.NONE)

        self._logger.info(f"Connection to {self.address}")

        # Reset packet counters
        self._outPacketCount = 2
        self._inPacketCount = 1

        # Reset protocol-specific state (important for reconnects).
        self._protocolMode = None
        self._dataCharUuid = None
        self._deviceProtocolVersion = None

        self._classicConnHash8 = None
        self._classicTxSeq = 0
        self._classicCmdDiv = 0
        self._classicHeaderMode = None
        self._classicTxCharUuid = None
        self._classicNotifyCharUuids.clear()
        self._classicHashSource = None
        self._classicFirstRxTs = None
        if self._classicNoRxTask is not None:
            self._classicNoRxTask.cancel()
            self._classicNoRxTask = None

        # Reset callback queue
        self._callbackQueue = asyncio.Queue()
        self._callbackTask = asyncio.create_task(self._processCallbacks())

        # To use bleak_retry_connector we need to have a BLEDevice so get one if we only have the address.
        device = (
            self._address_or_devive
            if isinstance(self._address_or_devive, BLEDevice)
            else await get_device(self.address)
        )

        if not device and isinstance(self._address_or_devive, str) and platform.system() == "Darwin":
            # macOS CoreBluetooth typically reports random per-device identifiers as addresses
            # unless `use_bdaddr` is enabled. Our `discover()` uses that flag so try it here.
            try:
                from ._discover import discover as discover_networks  # local import to avoid cycles

                networks = await discover_networks()
                wanted = self.address.replace(":", "").lower()
                for d in networks:
                    if d.address.replace(":", "").lower() == wanted:
                        device = d
                        break

                if not device:
                    self._logger.warning(
                        "macOS BLE lookup by address failed. Discovered %d Casambi networks, but none match %s. Discovered=%s",
                        len(networks),
                        self.address,
                        [d.address for d in networks[:10]],
                    )
            except Exception:
                self._logger.debug(
                    "macOS fallback discovery failed while trying to find %s.",
                    self.address,
                    exc_info=True,
                )

        if not device:
            self._logger.error("Failed to discover client.")
            raise NetworkNotFoundError

        try:
            # If we are already connected to the device the key exchange will fail.
            await close_stale_connections(device)
            # TODO: Should we try to get access to the network name here?
            self._gattClient = await establish_connection(
                BleakClient, device, "Casambi Network", self._on_disconnect
            )
        except BleakNotFoundError as e:
            # Guess that this is the error reason since ther are no better error types
            self._logger.error("Failed to find client.", exc_info=True)
            raise NetworkNotFoundError from e
        except BleakError as e:
            self._logger.error("Failed to connect.", exc_info=True)
            raise BluetoothError(e.args) from e
        except Exception as e:
            self._logger.error("Unkown connection failure.", exc_info=True)
            raise BluetoothError from e

        self._logger.info(f"Connected to {self.address}")
        self._connectionState = ConnectionState.CONNECTED

        # Detect protocol mode.
        #
        # Important: Home Assistant wraps BleakClient (HaBleakClientWrapper) which does not implement
        # `get_services()`. Therefore we use "try-read" probing instead of enumerating GATT services.
        #
        # Order:
        #  1) Classic "non-conformant": CA51 (hash) + CA52 (data channel)
        #  2) EVO: auth char read starts with 0x01 (NodeInfo)
        #  3) Classic "conformant": auth char read returns connection hash (first 8 bytes used)

        cloud_protocol = getattr(self._network, "protocolVersion", None)
        ca51_prefix: bytes | None = None
        ca51_err: str | None = None
        ca52_notify_err: str | None = None
        ca53_notify_err: str | None = None
        auth_prefix: bytes | None = None
        auth_err: str | None = None
        c0002_prefix: bytes | None = None
        c0002_err: str | None = None
        c0003_notify_err: str | None = None
        device_nodeinfo_protocol: int | None = None

        def _log_probe_summary(mode: str, *, classic_variant: str | None = None) -> None:
            # One stable, high-signal line for testers.
            self._logger.warning(
                "[CASAMBI_PROTOCOL_PROBE] address=%s mode=%s cloud_protocol=%s nodeinfo_b1=%s data_uuid=%s "
                "classic_variant=%s hash_source=%s classic_tx_uuid=%s classic_notify_uuids=%s "
                "ca51_hash8_present=%s conn_hash8_ready=%s "
                "auth_read_prefix=%s ca51_read_prefix=%s ca51_read_error=%s auth_read_error=%s "
                "ca52_notify_error=%s ca53_notify_error=%s c0002_read_prefix=%s c0002_read_error=%s c0003_notify_error=%s",
                self.address,
                mode,
                cloud_protocol,
                device_nodeinfo_protocol,
                self._dataCharUuid,
                classic_variant,
                self._classicHashSource,
                self._classicTxCharUuid,
                sorted(self._classicNotifyCharUuids) if self._classicNotifyCharUuids else None,
                bool(classic_hash and len(classic_hash) >= 8),
                self._classicConnHash8 is not None,
                auth_prefix,
                ca51_prefix,
                ca51_err,
                auth_err,
                ca52_notify_err,
                ca53_notify_err,
                c0002_prefix,
                c0002_err,
                c0003_notify_err,
            )

        classic_hash: bytes | None = None
        try:
            classic_hash = await self._gattClient.read_gatt_char(CASA_CLASSIC_HASH_CHAR_UUID)
            ca51_prefix = b2a(classic_hash[:10]) if classic_hash else None
            if self._logger.isEnabledFor(logging.DEBUG):
                self._logger.debug(
                    "[CASAMBI_GATT_PROBE] read ca51 ok len=%d prefix=%s",
                    0 if classic_hash is None else len(classic_hash),
                    ca51_prefix,
                )
        except Exception as e:
            classic_hash = None
            ca51_err = type(e).__name__
            if self._logger.isEnabledFor(logging.DEBUG):
                self._logger.debug("[CASAMBI_GATT_PROBE] read ca51 fail err=%s", ca51_err)

        if classic_hash and len(classic_hash) >= 8:
            self._protocolMode = ProtocolMode.CLASSIC
            self._dataCharUuid = CASA_CLASSIC_DATA_CHAR_UUID
            self._classicTxCharUuid = CASA_CLASSIC_DATA_CHAR_UUID
            self._classicHeaderMode = "legacy"
            self._classicHashSource = "ca51"

            # Read connection hash (first 8 bytes are used for CMAC signing).
            raw_hash = classic_hash
            if raw_hash is None or len(raw_hash) < 8:
                raise ClassicHandshakeError(
                    f"Classic connection hash read failed/too short (len={0 if raw_hash is None else len(raw_hash)})."
                )
            self._classicConnHash8 = bytes(raw_hash[:8])

            # Parse Android's extended connection hash fields for diagnostics.
            # Offset 8: unitId, 9: flags_lo, 10: MTU, 11: protocolVersion, 12: flags_hi
            if len(raw_hash) >= 13:
                ext_unit_id = raw_hash[8]
                ext_flags_lo = raw_hash[9]
                ext_mtu = raw_hash[10]
                ext_proto_ver = raw_hash[11]
                ext_flags_hi = raw_hash[12]
                self._logger.warning(
                    "[CASAMBI_CLASSIC_CONN_HASH_EXT] variant=legacy unitId=%d flags=0x%04x mtu=%d protocolVersion=%d raw=%s",
                    ext_unit_id,
                    (ext_flags_hi << 8) | ext_flags_lo,
                    ext_mtu,
                    ext_proto_ver,
                    b2a(bytes(raw_hash[:min(len(raw_hash), 20)])),
                )

            # Android seeds the command divider with a random byte on startup (u1.C1751c).
            self._classicCmdDiv = int.from_bytes(os.urandom(1), "big") or 1
            self._classicTxSeq = 0

            # Start notify on the data channel.
            notify_kwargs: dict[str, Any] = {}
            notify_params = inspect.signature(self._gattClient.start_notify).parameters
            if "bluez" in notify_params:
                notify_kwargs["bluez"] = {"use_start_notify": True}
            try:
                await self._gattClient.start_notify(
                    CASA_CLASSIC_DATA_CHAR_UUID,
                    self._queueCallback,
                    **notify_kwargs,
                )
            except Exception as e:
                ca52_notify_err = type(e).__name__
                # Some firmwares may expose Classic signing on the EVO UUID instead.
                # Fall through to auth-char probing if CA52 isn't available.
                if self._logger.isEnabledFor(logging.DEBUG):
                    self._logger.debug(
                        "[CASAMBI_GATT_PROBE] start_notify ca52 fail err=%s; trying auth UUID probing.",
                        type(e).__name__,
                        exc_info=True,
                    )
                self._protocolMode = None
                self._dataCharUuid = None
                self._classicConnHash8 = None
                self._classicTxCharUuid = None
                self._classicNotifyCharUuids.clear()
                self._classicHeaderMode = None
                self._classicHashSource = None
                # continue detection below
            else:
                self._classicNotifyCharUuids.add(CASA_CLASSIC_DATA_CHAR_UUID.lower())
                # Some Classic firmwares also expose state/config notifications on CA53.
                try:
                    await self._gattClient.start_notify(
                        CASA_CLASSIC_CA53_CHAR_UUID,
                        self._queueCallback,
                        **notify_kwargs,
                    )
                except Exception as e:
                    ca53_notify_err = type(e).__name__
                else:
                    self._classicNotifyCharUuids.add(CASA_CLASSIC_CA53_CHAR_UUID.lower())

                # Classic has no EVO-style key exchange/auth; we can send immediately.
                self._connectionState = ConnectionState.AUTHENTICATED
                self._logger.info("Protocol mode selected: CLASSIC")
                if self._logger.isEnabledFor(logging.DEBUG):
                    self._logger.debug("[CASAMBI_GATT_PROBE] start_notify ca52 ok")
                    self._logger.debug(
                        "[CASAMBI_CLASSIC_CONN_HASH] len=%d hash=%s",
                        len(self._classicConnHash8),
                        b2a(self._classicConnHash8),
                    )
                self._logger.warning(
                    "[CASAMBI_CLASSIC_SELECTED] address=%s variant=ca52_legacy data_uuid=%s tx_uuid=%s notify_uuids=%s header_mode=%s conn_hash8_prefix=%s",
                    self.address,
                    self._dataCharUuid,
                    self._classicTxCharUuid,
                    sorted(self._classicNotifyCharUuids) if self._classicNotifyCharUuids else None,
                    self._classicHeaderMode,
                    b2a(self._classicConnHash8),
                )
                self._logger.warning(
                    "[CASAMBI_CLASSIC_KEYS] visitor=%s manager=%s cloud_session_is_manager=%s",
                    self._network.classicVisitorKey() is not None,
                    self._network.classicManagerKey() is not None,
                    getattr(self._network, "isManager", lambda: False)(),
                )
                await self._classicEnumerateAndSubscribeGatt(notify_kwargs)
                _log_probe_summary("CLASSIC", classic_variant="ca52_legacy")
                # Emit a warning if we never see Classic RX frames; this is a common failure mode.
                self._classicNoRxTask = asyncio.create_task(self._classic_no_rx_watchdog(30.0))
                return

        # Conformant devices can expose the Classic signed channel on the EVO-style UUID too.
        first: bytes | None = None
        try:
            first = await self._gattClient.read_gatt_char(CASA_AUTH_CHAR_UUID)
            auth_prefix = b2a(first[:10]) if first else None
            if self._logger.isEnabledFor(logging.DEBUG):
                self._logger.debug(
                    "[CASAMBI_GATT_PROBE] read auth ok len=%d first_byte=%s prefix=%s",
                    0 if first is None else len(first),
                    None if not first else f"0x{first[0]:02x}",
                    auth_prefix,
                )
        except Exception as e:
            first = None
            auth_err = type(e).__name__
            if self._logger.isEnabledFor(logging.DEBUG):
                self._logger.debug("[CASAMBI_GATT_PROBE] read auth fail err=%s", auth_err)

        if first and len(first) >= 2 and first[0] == 0x01:
            # EVO NodeInfo packet starts with 0x01.
            device_nodeinfo_protocol = first[1]
            self._deviceProtocolVersion = device_nodeinfo_protocol
            mtu = unit = flags = None
            nonce_prefix = None
            if len(first) >= 23:
                try:
                    mtu, unit, flags, nonce = struct.unpack_from(">BHH16s", first, 2)
                    nonce_prefix = b2a(nonce[:8])
                except Exception:
                    if self._logger.isEnabledFor(logging.DEBUG):
                        self._logger.debug("Failed to parse NodeInfo fields for logging.", exc_info=True)

            self._logger.info(
                "[CASAMBI_EVO_NODEINFO] cloud_protocol=%s nodeinfo_b1=%s mtu=%s unit=%s flags=%s nonce_prefix=%s len=%d prefix=%s",
                cloud_protocol,
                device_nodeinfo_protocol,
                mtu,
                unit,
                None if flags is None else f"0x{flags:04x}",
                nonce_prefix,
                len(first),
                b2a(first[: min(len(first), 32)]),
            )
            if len(first) < 23:
                self._logger.warning(
                    "[CASAMBI_EVO_NODEINFO_SHORT] len=%d cloud_protocol=%s nodeinfo_b1=%s prefix=%s",
                    len(first),
                    cloud_protocol,
                    device_nodeinfo_protocol,
                    b2a(first[: min(len(first), 32)]),
                )

            self._protocolMode = ProtocolMode.EVO
            self._dataCharUuid = CASA_AUTH_CHAR_UUID
            self._classicHeaderMode = None
            self._logger.info("Protocol mode selected: EVO")
            _log_probe_summary("EVO")
            return

        if first is not None:
            # Otherwise, treat as Classic conformant: read provides connection hash.
            if len(first) < 8:
                raise ClassicHandshakeError(
                    f"Classic connection hash read failed/too short (len={len(first)})."
                )

            self._protocolMode = ProtocolMode.CLASSIC
            self._dataCharUuid = CASA_AUTH_CHAR_UUID
            self._classicTxCharUuid = CASA_AUTH_CHAR_UUID
            self._classicHeaderMode = "conformant"
            self._classicHashSource = "ca52_0001"
            self._classicConnHash8 = bytes(first[:8])

            # Parse Android's extended connection hash fields for diagnostics.
            # Offset 8: unitId, 9: flags_lo, 10: MTU, 11: protocolVersion, 12: flags_hi
            if len(first) >= 13:
                ext_unit_id = first[8]
                ext_flags_lo = first[9]
                ext_mtu = first[10]
                ext_proto_ver = first[11]
                ext_flags_hi = first[12]
                self._logger.warning(
                    "[CASAMBI_CLASSIC_CONN_HASH_EXT] variant=conformant unitId=%d flags=0x%04x mtu=%d protocolVersion=%d raw=%s",
                    ext_unit_id,
                    (ext_flags_hi << 8) | ext_flags_lo,
                    ext_mtu,
                    ext_proto_ver,
                    b2a(bytes(first[:min(len(first), 20)])),
                )

            self._classicCmdDiv = int.from_bytes(os.urandom(1), "big") or 1
            self._classicTxSeq = 0

            # Probe mapped Classic CA51 (0002) for diagnostics; some firmwares use it for time/config.
            try:
                v = await self._gattClient.read_gatt_char(CASA_CLASSIC_CONFORMANT_CA51_CHAR_UUID)
                c0002_prefix = b2a(v[:10]) if v else None
                if self._logger.isEnabledFor(logging.DEBUG):
                    self._logger.debug(
                        "[CASAMBI_GATT_PROBE] read classic-0002 ok len=%d prefix=%s",
                        0 if v is None else len(v),
                        c0002_prefix,
                    )
            except Exception as e:
                c0002_err = type(e).__name__
                if self._logger.isEnabledFor(logging.DEBUG):
                    self._logger.debug(
                        "[CASAMBI_GATT_PROBE] read classic-0002 fail err=%s",
                        c0002_err,
                    )

            notify_kwargs: dict[str, Any] = {}
            notify_params = inspect.signature(self._gattClient.start_notify).parameters
            if "bluez" in notify_params:
                notify_kwargs["bluez"] = {"use_start_notify": True}
            try:
                await self._gattClient.start_notify(
                    CASA_AUTH_CHAR_UUID,
                    self._queueCallback,
                    **notify_kwargs,
                )
            except Exception as e:
                ca52_notify_err = type(e).__name__
            else:
                self._classicNotifyCharUuids.add(CASA_AUTH_CHAR_UUID.lower())

            # Probe mapped Classic CA53 (0003) notify: some firmwares may emit state/config here.
            try:
                await self._gattClient.start_notify(
                    CASA_CLASSIC_CONFORMANT_CA53_CHAR_UUID,
                    self._queueCallback,
                    **notify_kwargs,
                )
            except Exception as e:
                c0003_notify_err = type(e).__name__
            else:
                self._classicNotifyCharUuids.add(CASA_CLASSIC_CONFORMANT_CA53_CHAR_UUID.lower())

            self._connectionState = ConnectionState.AUTHENTICATED
            self._logger.info("Protocol mode selected: CLASSIC")
            if self._logger.isEnabledFor(logging.DEBUG):
                if ca52_notify_err is None:
                    self._logger.debug("[CASAMBI_GATT_PROBE] start_notify auth ok (classic conformant)")
                else:
                    self._logger.debug(
                        "[CASAMBI_GATT_PROBE] start_notify auth fail err=%s (classic conformant)",
                        ca52_notify_err,
                    )
                self._logger.debug(
                    "[CASAMBI_CLASSIC_CONN_HASH] len=%d hash=%s",
                    len(self._classicConnHash8),
                    b2a(self._classicConnHash8),
                )
            self._logger.warning(
                "[CASAMBI_CLASSIC_SELECTED] address=%s variant=auth_uuid_conformant data_uuid=%s tx_uuid=%s notify_uuids=%s header_mode=%s conn_hash8_prefix=%s",
                self.address,
                self._dataCharUuid,
                self._classicTxCharUuid,
                sorted(self._classicNotifyCharUuids) if self._classicNotifyCharUuids else None,
                self._classicHeaderMode,
                b2a(self._classicConnHash8),
            )
            self._logger.warning(
                "[CASAMBI_CLASSIC_KEYS] visitor=%s manager=%s cloud_session_is_manager=%s",
                self._network.classicVisitorKey() is not None,
                self._network.classicManagerKey() is not None,
                getattr(self._network, "isManager", lambda: False)(),
            )
            await self._classicEnumerateAndSubscribeGatt(notify_kwargs)
            _log_probe_summary("CLASSIC", classic_variant="auth_uuid_conformant")
            self._classicNoRxTask = asyncio.create_task(self._classic_no_rx_watchdog(30.0))
            return

        _log_probe_summary("UNKNOWN")
        raise ProtocolError(
            "No supported Casambi characteristics found (Classic ca51/ca52 or EVO/Classic-conformant auth char)."
        )

    async def _classic_no_rx_watchdog(self, after_s: float) -> None:
        """Emit one high-signal log if Classic RX stays silent after connect.

        This helps testers capture actionable logs when Classic control/updates don't work yet.
        """
        try:
            await asyncio.sleep(after_s)
            if self._protocolMode != ProtocolMode.CLASSIC:
                return
            if self._classicFirstRxTs is not None:
                return

            self._logger.warning(
                "[CASAMBI_CLASSIC_NO_RX] after_s=%s notify_uuids=%s tx_uuid=%s header_mode=%s "
                "conn_hash8_prefix=%s visitor=%s manager=%s cloud_session_is_manager=%s",
                after_s,
                sorted(self._classicNotifyCharUuids) if self._classicNotifyCharUuids else None,
                self._classicTxCharUuid,
                self._classicHeaderMode,
                None if self._classicConnHash8 is None else b2a(self._classicConnHash8),
                self._network.classicVisitorKey() is not None,
                self._network.classicManagerKey() is not None,
                getattr(self._network, "isManager", lambda: False)(),
            )
        except asyncio.CancelledError:
            return
        except Exception:
            # Never fail the connection because of diagnostics.
            self._logger.debug("Classic no-RX watchdog failed.", exc_info=True)

    def _on_disconnect(self, client: BleakClient) -> None:
        if self._connectionState != ConnectionState.NONE:
            self._logger.info(f"Received disconnect callback from {self.address}")
        if self._connectionState == ConnectionState.AUTHENTICATED:
            self._logger.debug("Executing disconnect callback.")
            self._disconnectedCallback()
        if self._classicNoRxTask is not None:
            self._classicNoRxTask.cancel()
            self._classicNoRxTask = None
        self._connectionState = ConnectionState.NONE

    async def exchangeKey(self) -> None:
        self._checkState(ConnectionState.CONNECTED)

        self._logger.info("Starting key exchange...")

        await self._activityLock.acquire()
        try:
            # Initiate communication with device
            firstResp = await self._gattClient.read_gatt_char(CASA_AUTH_CHAR_UUID)
            if self._logger.isEnabledFor(logging.DEBUG):
                self._logger.debug(
                    "[CASAMBI_EVO_NODEINFO_RAW] len=%d prefix=%s",
                    len(firstResp),
                    b2a(firstResp[: min(len(firstResp), 32)]),
                )

            cloud_protocol = getattr(self._network, "protocolVersion", None)

            # EVO key exchange expects the NodeInfo packet (0x01 ...).
            if len(firstResp) < 2 or firstResp[0] != 0x01:
                self._logger.error(
                    "[CASAMBI_EVO_NODEINFO_UNEXPECTED] expected_prefix=01 len=%d prefix=%s",
                    len(firstResp),
                    b2a(firstResp[: min(len(firstResp), 32)]),
                )
                raise ProtocolError("Unexpected NodeInfo response while starting key exchange.")

            device_protocol = firstResp[1]
            self._deviceProtocolVersion = device_protocol
            # Do not interpret NodeInfo byte1 as "cloud protocolVersion".
            # Some firmwares use a different numbering scheme, so mismatch warnings are misleading.

            if len(firstResp) < 23:
                self._logger.error(
                    "[CASAMBI_EVO_NODEINFO_SHORT] len=%d cloud_protocol=%s nodeinfo_b1=%s prefix=%s",
                    len(firstResp),
                    cloud_protocol,
                    device_protocol,
                    b2a(firstResp[: min(len(firstResp), 32)]),
                )
                raise ProtocolError("NodeInfo response too short while starting key exchange.")

            # Parse device info
            self._mtu, self._unit, self._flags, self._nonce = struct.unpack_from(
                ">BHH16s", firstResp, 2
            )
            self._logger.debug(
                f"Parsed mtu {self._mtu}, unit {self._unit}, flags {self._flags}, nonce {b2a(self._nonce)}"
            )

            # Device will initiate key exchange, so listen for that
            self._logger.debug("Starting notify")
            notify_kwargs: dict[str, Any] = {}
            notify_params = inspect.signature(self._gattClient.start_notify).parameters
            if "bluez" in notify_params:
                notify_kwargs["bluez"] = {"use_start_notify": True}

            await self._gattClient.start_notify(
                CASA_AUTH_CHAR_UUID,
                self._queueCallback,
                **notify_kwargs,
            )
        finally:
            self._activityLock.release()

        # Wait for key exchange, will get notified by _exchNotifyCallback
        await self._notifySignal.wait()
        await self._activityLock.acquire()
        try:
            self._notifySignal.clear()
            if self._connectionState == ConnectionState.ERROR:
                raise ProtocolError("Invalid key exchange initiation.")

            # Respond to key exchange
            pubNums = self._pubKey.public_numbers()
            keyExchResponse = struct.pack(
                ">B32s32sB",
                0x2,
                pubNums.x.to_bytes(32, byteorder="little", signed=False),
                pubNums.y.to_bytes(32, byteorder="little", signed=False),
                0x1,
            )
            await self._gattClient.write_gatt_char(CASA_AUTH_CHAR_UUID, keyExchResponse)
        finally:
            self._activityLock.release()

        # Wait for success response from _exchNotifyCallback
        await self._notifySignal.wait()
        await self._activityLock.acquire()
        try:
            self._notifySignal.clear()
            if self._connectionState == ConnectionState.ERROR:  # type: ignore[comparison-overlap]
                raise ProtocolError("Failed to negotiate key!")
            else:
                self._logger.info("Key exchange sucessful")
                self._encryptor = Encryptor(self._transportKey)

                # Skip auth if the network doesn't use a key.
                if self._network.keyStore.getKey():
                    self._connectionState = ConnectionState.KEY_EXCHANGED
                else:
                    self._connectionState = ConnectionState.AUTHENTICATED
        finally:
            self._activityLock.release()

    def _queueCallback(self, handle: BleakGATTCharacteristic, data: bytes) -> None:
        self._callbackQueue.put_nowait((handle, data))

    async def _processCallbacks(self) -> None:
        try:
            while True:
                handle, data = await self._callbackQueue.get()

                # Try to loose any races here.
                # Otherwise a state change caused by the last packet might not have been handled yet
                await asyncio.sleep(0.001)
                await self._activityLock.acquire()
                try:
                    self._callbackMulitplexer(handle, data)
                finally:
                    self._callbackQueue.task_done()
                    self._activityLock.release()
        except asyncio.CancelledError:
            # Task cancelled during shutdown; log at debug and exit cleanly.
            self._logger.debug("Callback processing task cancelled during shutdown.")
            raise

    def _callbackMulitplexer(
        self, handle: BleakGATTCharacteristic, data: bytes
    ) -> None:
        if self._connectionState == ConnectionState.CONNECTED:
            self._exchNofityCallback(handle, data)
        elif self._connectionState == ConnectionState.KEY_EXCHANGED:
            self._authNofityCallback(handle, data)
        elif self._connectionState == ConnectionState.AUTHENTICATED:
            self._establishedNofityCallback(handle, data)
        else:
            self._logger.warning(
                f"Unhandled notify in state {self._connectionState}: {b2a(data)}"
            )

    def _exchNofityCallback(self, handle: BleakGATTCharacteristic, data: bytes) -> None:
        if data[0] == 0x2:
            # Parse device pubkey
            x, y = struct.unpack_from("<32s32s", data, 1)
            x = int.from_bytes(x, byteorder="little")
            y = int.from_bytes(y, byteorder="little")
            self._logger.debug(f"Got public key {x}, {y}")

            self._devicePubKey = ec.EllipticCurvePublicNumbers(
                x, y, ec.SECP256R1()
            ).public_key()

            # Generate key pair for client
            self._privKey = ec.generate_private_key(ec.SECP256R1())
            self._pubKey = self._privKey.public_key()

            # Generate shared secret
            secret = bytearray(self._privKey.exchange(ec.ECDH(), self._devicePubKey))
            secret.reverse()
            hashAlgo = sha256()
            hashAlgo.update(secret)
            digestedSecret = hashAlgo.digest()

            # Compute transport key
            self._transportKey = bytearray()
            for i in range(16):
                self._transportKey.append(digestedSecret[i] ^ digestedSecret[16 + i])

            # Inform exchangeKey that packet has been parsed
            self._notifySignal.set()

        elif data[0] == 0x3:
            if len(data) == 1:
                # Key exchange is acknowledged by device
                self._notifySignal.set()
            else:
                self._logger.error(
                    f"Unexpected package length for key exchange response: {b2a(data)}"
                )
                self._connectionState = ConnectionState.ERROR
                self._notifySignal.set()
        else:
            self._logger.error(f"Unexcpedted package type in {b2a(data)}.")
            self._connectionState = ConnectionState.ERROR
            self._notifySignal.set()

    async def authenticate(self) -> None:
        self._checkState(ConnectionState.KEY_EXCHANGED)

        self._logger.info("Authenicating channel...")
        key = self._network.keyStore.getKey()  # Session key

        if not key:
            self._logger.info("No key in keystore. Skipping auth.")
            # The channel already has to be set to authenticated by exchangeKey.
            # This needs to be done there a non-handshake packet could be sent right after acking the key exch
            # and we don't want that packet to end up in _authNofityCallback.
            return

        await self._activityLock.acquire()
        try:
            # Compute client auth digest
            hashFcnt = sha256()
            hashFcnt.update(key.key)
            hashFcnt.update(self._nonce)
            hashFcnt.update(self._transportKey)
            authDig = hashFcnt.digest()
            self._logger.debug(f"Auth digest: {b2a(authDig)}")

            # Send auth packet
            authPacket = int.to_bytes(1, 4, "little")
            authPacket += b"\x04"
            authPacket += key.id.to_bytes(1, "little")
            authPacket += authDig
            await self._writeEncPacket(authPacket, 1, CASA_AUTH_CHAR_UUID)
        finally:
            self._activityLock.release()

        # Wait for auth response
        await self._notifySignal.wait()

        await self._activityLock.acquire()
        try:
            self._notifySignal.clear()
            if self._connectionState == ConnectionState.ERROR:
                raise ProtocolError("Failed to verify authentication response.")
            else:
                self._connectionState = ConnectionState.AUTHENTICATED
                self._logger.info("Authentication successful")
        finally:
            self._activityLock.release()

    def _authNofityCallback(self, handle: BleakGATTCharacteristic, data: bytes) -> None:
        self._logger.info("Processing authentication response...")

        # TODO: Verify counter
        self._inPacketCount += 1

        try:
            self._encryptor.decryptAndVerify(data, data[:4] + self._nonce[4:])
        except InvalidSignature:
            self._logger.fatal("Invalid signature for auth response!")
            self._connectionState = ConnectionState.ERROR
            return

        # TODO: Verify Digest 2 (to compare with response from device); SHA256(key.key||self pubKey point||self._transportKey)

        self._notifySignal.set()

    async def _writeEncPacket(
        self, packet: bytes, id: int, char: str | BleakGATTCharacteristic
    ) -> None:
        encPacket = self._encryptor.encryptThenMac(packet, self._getNonce(id))
        try:
            await self._gattClient.write_gatt_char(char, encPacket)
        except BleakError as e:
            if e.args[0] == "Not connected":
                self._connectionState = ConnectionState.NONE
            else:
                raise e

    def _getNonce(self, id: int | bytes) -> bytes:
        if isinstance(id, int):
            id = id.to_bytes(4, "little")
        return self._nonce[:4] + id + self._nonce[8:]

    async def send(self, packet: bytes) -> None:
        # EVO sends INVOCATION operations (packet type=0x07) inside the encrypted channel.
        # Classic sends signed command frames on the CA52 channel.
        if self._protocolMode == ProtocolMode.CLASSIC:
            await self._sendClassic(packet)
            return

        self._checkState(ConnectionState.AUTHENTICATED)

        await self._activityLock.acquire()
        try:
            self._logger.debug(
                f"Sending packet {b2a(packet)} with counter {self._outPacketCount}"
            )

            counter = int.to_bytes(self._outPacketCount, 4, "little")
            headerPaket = counter + b"\x07" + packet

            self._logger.debug(f"Packet with header: {b2a(headerPaket)}")

            await self._writeEncPacket(
                headerPaket, self._outPacketCount, CASA_AUTH_CHAR_UUID
            )
            self._outPacketCount += 1
        finally:
            self._activityLock.release()

    def _classic_next_seq(self) -> int:
        # 16-bit sequence inserted in the header (big endian) and included in CMAC input.
        self._classicTxSeq = (self._classicTxSeq + 1) & 0xFFFF
        if self._classicTxSeq == 0:
            self._classicTxSeq = 1
        return self._classicTxSeq

    def _classic_next_div(self) -> int:
        # 8-bit command divider/id. Android uses a random start and increments 1..255.
        self._classicCmdDiv += 1
        if self._classicCmdDiv == 0 or self._classicCmdDiv > 255:
            self._classicCmdDiv = 1
        return self._classicCmdDiv

    def buildClassicCommand(
        self,
        command_ordinal: int,
        payload: bytes,
        *,
        target_id: int | None = None,
        lifetime: int = 200,
        div: int | None = None,
    ) -> bytes:
        """Build one Classic command record (u1.C1753e export format).

        This is the message that follows the Classic signed header and 16-bit sequence.
        """
        if div is None:
            div = self._classic_next_div()
        if div < 0 or div > 255:
            raise ValueError("div must fit in one byte")
        if lifetime < 0 or lifetime > 255:
            raise ValueError("lifetime must fit in one byte")
        if target_id is not None and (target_id < 0 or target_id > 255):
            raise ValueError("target_id must fit in one byte")

        # Two leading bytes are patched after we know the final length:
        # - byte0 = (len + 239) mod 256
        # - byte1 = ordinal | 0x40 (div present) | 0x80 (target present)
        b = bytearray()
        b.append(0)
        b.append(0)

        type_flags = command_ordinal & 0x3F

        # div present
        b.append(div & 0xFF)
        type_flags |= 0x40

        if target_id is not None and target_id > 0:
            b.append(target_id & 0xFF)
            type_flags |= 0x80

        b.append(lifetime & 0xFF)
        b.extend(payload)

        msg_len = len(b)
        b[0] = (msg_len + 239) & 0xFF
        b[1] = type_flags & 0xFF

        if self._logger.isEnabledFor(logging.DEBUG):
            self._logger.debug(
                "[CASAMBI_CLASSIC_CMD_BUILD] ord=%d target=%s div=%d lifetime=%d len=%d payload=%s",
                command_ordinal,
                target_id,
                div,
                lifetime,
                msg_len,
                b2a(payload),
            )

        return bytes(b)

    def buildClassicCommandSimple(
        self,
        unit_id: int,
        dimmer: int,
        extra: int | None = None,
    ) -> bytes:
        """Build a Classic command using the simple format from BLE captures.

        This alternative format was observed in real BLE captures and differs from
        the Android u1.C1753e command record format. Use with env variable
        CASAMBI_BT_CLASSIC_FORMAT=simple to experiment.

        Format (before header added by _sendClassic):
        [counter:1][unit_id:1][param_len:1][dimmer:1][extra:1?]

        The header (added by _sendClassic) is:
        - Conformant: [auth:1][cmac:4|16][seq:2]
        - Legacy: [cmac:4]

        Args:
            unit_id: Target unit ID (0-255, use 0xFF for "all units")
            dimmer: Dimmer/level value (0-255)
            extra: Optional extra parameter (e.g., temperature/vertical value)

        Returns:
            Command bytes to pass to _sendClassic
        """
        counter = self._classic_next_div()
        if extra is not None:
            return bytes([counter, unit_id & 0xFF, 2, dimmer & 0xFF, extra & 0xFF])
        else:
            return bytes([counter, unit_id & 0xFF, 1, dimmer & 0xFF])

    async def _sendClassic(self, command_bytes: bytes, *, target_uuid: str | None = None) -> None:
        self._checkState(ConnectionState.AUTHENTICATED)
        if self._protocolMode != ProtocolMode.CLASSIC:
            raise ProtocolError("Classic send called while not in Classic protocol mode.")
        tx_uuid = target_uuid or self._classicTxCharUuid or self._dataCharUuid
        if not tx_uuid:
            raise ProtocolError("Classic TX characteristic UUID not set.")
        if self._classicConnHash8 is None:
            raise ClassicHandshakeError("Classic connection hash not available.")

        visitor_key = self._network.classicVisitorKey()
        manager_key = self._network.classicManagerKey()

        # Parse the command record for logs (u1.C1753e export format).
        cmd_ordinal: int | None = None
        cmd_div: int | None = None
        cmd_target: int | None = None
        cmd_lifetime: int | None = None
        cmd_payload_len: int | None = None
        try:
            if len(command_bytes) >= 2:
                typ = command_bytes[1]
                cmd_ordinal = typ & 0x3F
                has_div = (typ & 0x40) != 0
                has_target = (typ & 0x80) != 0
                p = 2
                if has_div and p < len(command_bytes):
                    cmd_div = command_bytes[p]
                    p += 1
                if has_target and p < len(command_bytes):
                    cmd_target = command_bytes[p]
                    p += 1
                if p < len(command_bytes):
                    cmd_lifetime = command_bytes[p]
                    p += 1
                if p <= len(command_bytes):
                    cmd_payload_len = len(command_bytes) - p
        except Exception:
            # If parsing fails, keep fields as None.
            pass

        # Key selection mirrors Android's intent:
        # - Use manager key if our cloud session is manager and a managerKey exists.
        # - Else use visitor key if present.
        # - Else fall back to manager key if present.
        # - Else send an unsigned frame (signature bytes remain zeros), which Android does when keys are null.
        key_name = "none"
        auth_level = 0x02  # visitor by default
        key = None
        if manager_key is not None and getattr(self._network, "isManager", lambda: False)():
            key_name = "manager"
            auth_level = 0x03
            key = manager_key
        elif visitor_key is not None:
            key_name = "visitor"
            auth_level = 0x02
            key = visitor_key
        elif manager_key is not None:
            key_name = "manager"
            auth_level = 0x03
            key = manager_key

        header_mode = self._classicHeaderMode or "conformant"

        seq: int | None = None
        sig_len: int
        pkt = bytearray()

        if header_mode == "conformant":
            sig_len = 16 if auth_level == 0x03 else 4
            seq = self._classic_next_seq()

            # Header layout (rVar.Z=true / "conformant" classic):
            #   [0] auth_level (2 visitor / 3 manager)
            #   [1..sig_len] CMAC prefix placeholder (filled after CMAC computation)
            #   [1+sig_len .. 1+sig_len+1] 16-bit sequence, big endian (included in CMAC input)
            #   [..] command bytes
            pkt.append(auth_level)
            pkt.extend(b"\x00" * sig_len)
            pkt.extend(b"\x00\x00")
            pkt.extend(command_bytes)

            seq_off = 1 + sig_len
            pkt[seq_off] = (seq >> 8) & 0xFF
            pkt[seq_off + 1] = seq & 0xFF

            if key is not None:
                cmac_input = bytes(pkt[seq_off:])  # includes seq + command bytes
                prefix = classic_cmac_prefix(key, self._classicConnHash8, cmac_input, sig_len)
                pkt[1 : 1 + sig_len] = prefix

        elif header_mode == "legacy":
            # Legacy/non-conformant classic: only a 4-byte CMAC prefix, no auth byte, no seq.
            sig_len = 4
            pkt.extend(b"\x00" * sig_len)
            pkt.extend(command_bytes)

            if key is not None:
                cmac_input = bytes(command_bytes)
                prefix = classic_cmac_prefix(key, self._classicConnHash8, cmac_input, sig_len)
                pkt[0:sig_len] = prefix
        else:
            raise ProtocolError(f"Unknown Classic header mode: {header_mode}")

        signed = key is not None
        if not signed and self._logLimiter.allow("classic_tx_unsigned", burst=10, window_s=300.0):
            self._logger.warning(
                "[CASAMBI_CLASSIC_TX_UNSIGNED] reason=keys_missing visitor=%s manager=%s",
                visitor_key is not None,
                manager_key is not None,
            )

        # WARNING-level TX logs are intentional: they are needed for Classic reverse engineering.
        # Keep payload logging minimal (prefix only).
        if self._logLimiter.allow("classic_tx", burst=50, window_s=60.0):
            auth_str = f"0x{auth_level:02x}" if header_mode == "conformant" else None
            self._logger.warning(
                "[CASAMBI_CLASSIC_TX] header=%s key=%s signed=%s tx_uuid=%s auth=%s sig_len=%d seq=%s "
                "cmd_len=%d cmd_ord=%s target=%s div=%s lifetime=%s payload_len=%s "
                "total_len=%d prefix=%s",
                header_mode,
                key_name,
                signed,
                tx_uuid,
                auth_str,
                sig_len,
                None if seq is None else f"0x{seq:04x}",
                len(command_bytes),
                cmd_ordinal,
                cmd_target,
                cmd_div,
                cmd_lifetime,
                cmd_payload_len,
                len(pkt),
                b2a(bytes(pkt[: min(len(pkt), 24)])),
            )

        # Classic packets can exceed 20 bytes when using a 16-byte manager signature.
        # Bleak needs a write-with-response for long writes on most backends.
        tx_result = "pending"
        try:
            await self._gattClient.write_gatt_char(tx_uuid, bytes(pkt), response=True)
            tx_result = "ok"
        except Exception as e:
            tx_result = f"error: {type(e).__name__}: {e}"
            raise
        finally:
            # Record TX in diagnostic history
            tx_entry = {
                "timestamp": time.monotonic(),
                "header_mode": header_mode,
                "key": key_name,
                "signed": signed,
                "tx_uuid": tx_uuid,
                "auth_level": auth_level if header_mode == "conformant" else None,
                "sig_len": sig_len,
                "seq": seq,
                "cmd_ordinal": cmd_ordinal,
                "cmd_target": cmd_target,
                "cmd_div": cmd_div,
                "cmd_lifetime": cmd_lifetime,
                "cmd_payload_len": cmd_payload_len,
                "total_len": len(pkt),
                "pre_sign_hex": b2a(command_bytes).decode("ascii"),
                "post_sign_hex": b2a(bytes(pkt)).decode("ascii"),
                "result": tx_result,
            }
            self._classicTxHistory.append(tx_entry)
            if len(self._classicTxHistory) > self._classicDiagMaxHistory:
                self._classicTxHistory = self._classicTxHistory[-self._classicDiagMaxHistory:]

            # Enhanced TX diagnostic log
            self._logger.warning(
                "[CLASSIC_DIAG_TX_RESULT] result=%s header=%s seq=%s total_len=%d",
                tx_result,
                header_mode,
                None if seq is None else f"0x{seq:04x}",
                len(pkt),
            )

    async def _classicEnumerateAndSubscribeGatt(
        self, notify_kwargs: dict[str, Any]
    ) -> None:
        """Enumerate all GATT characteristics and subscribe to any notifiable ones.

        This discovers characteristics beyond the manually-probed CA51/CA52/CA53
        UUIDs and subscribes to any that support notify or indicate, which may be
        needed for receiving Classic state/config notifications.
        """
        try:
            total_chars = 0
            for svc in self._gattClient.services:
                for char in svc.characteristics:
                    total_chars += 1
                    char_uuid = str(char.uuid).lower()
                    props = char.properties
                    self._logger.warning(
                        "[CASAMBI_CLASSIC_GATT_CHAR] uuid=%s props=%s handle=%d",
                        char_uuid,
                        props,
                        char.handle,
                    )
                    if char_uuid not in self._classicNotifyCharUuids:
                        if "notify" in props or "indicate" in props:
                            try:
                                await self._gattClient.start_notify(
                                    char.uuid,
                                    self._queueCallback,
                                    **notify_kwargs,
                                )
                                self._classicNotifyCharUuids.add(char_uuid)
                                self._logger.warning(
                                    "[CASAMBI_CLASSIC_GATT_SUB] subscribed uuid=%s",
                                    char_uuid,
                                )
                            except Exception as e:
                                self._logger.warning(
                                    "[CASAMBI_CLASSIC_GATT_SUB] failed uuid=%s err=%s",
                                    char_uuid,
                                    type(e).__name__,
                                )
            self._logger.warning(
                "[CASAMBI_CLASSIC_GATT_ENUM] total_chars=%d subscribed_uuids=%s",
                total_chars,
                sorted(self._classicNotifyCharUuids),
            )
        except Exception as e:
            self._logger.warning(
                "[CASAMBI_CLASSIC_GATT_ENUM] services enumeration unavailable: %s",
                type(e).__name__,
            )

    async def classicSendInit(self) -> None:
        """Send Classic post-connection initialization (time-sync).

        Ground truth: casambi-android AbstractC1717h.X() (lines 254-345).
        The Android app sends this as the first packet after Classic connection.
        In EVO, the key exchange/auth handshake implicitly signals the device;
        Classic has no such handshake, so an explicit init write is needed to
        trigger the device to start broadcasting state notifications.

        The payload is sent raw via _sendClassic (NOT wrapped in buildClassicCommand).
        """
        self._checkState(ConnectionState.AUTHENTICATED)
        if self._protocolMode != ProtocolMode.CLASSIC:
            return

        import datetime as _dt

        now = _dt.datetime.now()

        # Timezone offset in minutes from UTC.
        local_tz = _dt.datetime.now(_dt.timezone.utc).astimezone().tzinfo
        utc_offset_minutes = 0
        if local_tz is not None:
            offset = local_tz.utcoffset(now)
            if offset is not None:
                utc_offset_minutes = int(offset.total_seconds()) // 60

        # Determine time-sync target and command byte per Android AbstractC1717h.X():
        # - Non-conformant: write to CA51, command byte 10
        # - Conformant: write to 0002 (mapped CA51), command byte 7
        if self._classicHeaderMode == "conformant":
            timesync_uuid = CASA_CLASSIC_CONFORMANT_CA51_CHAR_UUID  # 0002
            timesync_cmd = 7
        else:
            timesync_uuid = CASA_CLASSIC_HASH_CHAR_UUID  # CA51
            timesync_cmd = 10

        # Build the time-sync payload.
        # Format: [cmd][year:2BE][month:1][day:1][hour:1][min:1][sec:1]
        #         [tz_offset:2BE signed][dst_transition:4BE][dst_change:1]
        #         [timestamp1:3BE][timestamp2:3BE][zero:2][millis:3BE][extra:1]
        payload = bytearray()
        payload.append(timesync_cmd)
        payload.extend(struct.pack(">H", now.year))
        payload.append(now.month)
        payload.append(now.day)
        payload.append(now.hour)
        payload.append(now.minute)
        payload.append(now.second)
        payload.extend(struct.pack(">h", utc_offset_minutes))
        # DST transition data and change minutes (0 = no DST info).
        payload.extend(struct.pack(">I", 0))
        payload.append(0)
        # Classic extra bytes: timestamps, zero short, millis, trailing byte.
        # Android AbstractC1717h.X() lines 323-328: j() = 3-byte big-endian write
        # (Q2.t.java:59-63), NOT 4-byte. Plus trailing writeByte(iK0 >> 24).
        ts1 = 0  # Q2.r.K0(network.V) — start with 0
        ts2 = 0  # Q2.r.K0(network.W) — start with 0
        for ts in (ts1, ts2):
            payload.append((ts >> 16) & 0xFF)
            payload.append((ts >> 8) & 0xFF)
            payload.append(ts & 0xFF)
        payload.extend(struct.pack(">H", 0))  # writeShort(0)
        millis_val = now.microsecond // 1000 * 1000
        payload.append((millis_val >> 16) & 0xFF)
        payload.append((millis_val >> 8) & 0xFF)
        payload.append(millis_val & 0xFF)
        payload.append((ts1 >> 24) & 0xFF)  # writeByte(iK0 >> 24)

        self._logger.warning(
            "[CASAMBI_CLASSIC_INIT] sending time-sync len=%d cmd=%d target_uuid=%s header_mode=%s hex=%s",
            len(payload),
            timesync_cmd,
            timesync_uuid,
            self._classicHeaderMode,
            b2a(bytes(payload)),
        )

        try:
            await self._sendClassic(bytes(payload), target_uuid=timesync_uuid)
            self._logger.warning("[CASAMBI_CLASSIC_INIT] time-sync sent successfully")
        except Exception:
            self._logger.warning(
                "[CASAMBI_CLASSIC_INIT] time-sync send failed",
                exc_info=True,
            )

    def _establishedNofityCallback(
        self, handle: BleakGATTCharacteristic, data: bytes
    ) -> None:
        # Route notifications based on characteristic UUID when available.
        # This helps with mixed/legacy setups where multiple Classic channels might be active.
        try:
            handle_uuid = str(getattr(handle, "uuid", "")).lower()
        except Exception:
            handle_uuid = ""
        if handle_uuid and handle_uuid in self._classicNotifyCharUuids:
            self._classicEstablishedNotifyCallback(handle, data)
            return
        if self._protocolMode == ProtocolMode.CLASSIC:
            self._classicEstablishedNotifyCallback(handle, data)
            return

        # TODO: Check incoming counter and direction flag
        self._inPacketCount += 1

        # Store raw encrypted packet for reference
        raw_encrypted_packet = data[:]

        # Extract the device-provided 4-byte little-endian counter from the
        # encrypted header. This is the true per-session packet sequence.
        try:
            device_sequence = int.from_bytes(data[:4], byteorder="little", signed=False)
        except Exception:
            device_sequence = None

        try:
            decrypted_data = self._encryptor.decryptAndVerify(
                data, data[:4] + self._nonce[4:]
            )
        except InvalidSignature:
            # We only drop packets with invalid signature here instead of going into an error state
            self._logger.error(f"Invalid signature for packet {b2a(data)}!")
            return

        packetType = decrypted_data[0]
        if self._logger.isEnabledFor(logging.DEBUG):
            self._logger.debug(
                "Incoming data of type %d: %s", packetType, b2a(decrypted_data)
            )

        if packetType == IncommingPacketType.UnitState:
            self._parseUnitStates(decrypted_data[1:])
        elif packetType == IncommingPacketType.SwitchEvent:
            # Stable logs for offline analysis: packet seq + encrypted + decrypted.
            # (Decrypted data includes the leading packet type byte.)
            if self._logger.isEnabledFor(logging.DEBUG):
                self._logger.debug(
                    "[CASAMBI_RAW_PACKET] Encrypted #%s: %s",
                    device_sequence,
                    b2a(raw_encrypted_packet),
                )
                self._logger.debug(
                    "[CASAMBI_DECRYPTED] Type=%d #%s: %s",
                    packetType,
                    device_sequence,
                    b2a(decrypted_data),
                )
            # Pass the device sequence as the packet sequence for consumers,
            # and still include the raw encrypted packet for diagnostics.
            seq_for_consumer = device_sequence if device_sequence is not None else self._inPacketCount
            self._parseSwitchEvent(
                decrypted_data[1:], seq_for_consumer, raw_encrypted_packet
            )
        elif packetType == IncommingPacketType.NetworkConfig:
            # We don't care about the config the network thinks it has.
            # We assume that cloud config and local config match.
            # If there is a mismatch the user can solve it using the app.
            # In the future we might want to parse the revision and issue a warning if there is a mismatch.
            pass
        else:
            self._logger.debug("Packet type %d not implemented. Ignoring!", packetType)

    def _classicEstablishedNotifyCallback(
        self, handle: BleakGATTCharacteristic, data: bytes
    ) -> None:
        """Parse Classic notifications from the CA52 channel.

        Classic packets are CMAC-signed (prefix embedded into the header).
        Ground truth: casambi-android `t1.P.o(...)`.
        """
        self._inPacketCount += 1
        self._classicRxFrames += 1
        rx_ts = time.monotonic()
        if self._classicFirstRxTs is None:
            self._classicFirstRxTs = rx_ts

        raw = bytes(data)

        # Enhanced RX diagnostic logging
        try:
            handle_uuid = str(getattr(handle, "uuid", "unknown")).lower()
        except Exception:
            handle_uuid = "unknown"

        self._logger.warning(
            "[CLASSIC_DIAG_RX] #%d handle=%s len=%d hex=%s",
            self._classicRxFrames,
            handle_uuid,
            len(raw),
            b2a(raw[: min(len(raw), 48)]).decode("ascii") + ("..." if len(raw) > 48 else ""),
        )

        if self._logger.isEnabledFor(logging.DEBUG):
            self._logger.debug(
                "[CASAMBI_CLASSIC_RX_RAW] len=%d hex=%s",
                len(raw),
                b2a(raw[: min(len(raw), 64)]) + (b"..." if len(raw) > 64 else b""),
            )

        if self._classicConnHash8 is None:
            if self._logLimiter.allow("classic_rx_no_hash", burst=5, window_s=60.0):
                self._logger.warning("[CASAMBI_CLASSIC_RX] missing_connection_hash len=%d", len(raw))
            return

        visitor_key = self._network.classicVisitorKey()
        manager_key = self._network.classicManagerKey()

        def _plausible_payload(payload: bytes) -> bool:
            if not payload:
                return False
            if payload[0] in (
                IncommingPacketType.UnitState,
                IncommingPacketType.SwitchEvent,
                IncommingPacketType.NetworkConfig,
            ):
                return True
            # Classic command record stream: record[0] = (len+239) mod 256
            if len(payload) >= 2:
                rec_len = (payload[0] - 239) & 0xFF
                if 2 <= rec_len <= len(payload):
                    return True
            return False

        def _score(verified: bool | None, payload: bytes) -> int:
            plausible = _plausible_payload(payload)
            if verified is True:
                return 100
            if plausible and verified is None:
                return 50
            if plausible and verified is False:
                return 20
            return 0

        def _parse_conformant(raw_bytes: bytes) -> dict[str, Any] | None:
            if len(raw_bytes) < 1 + 4 + 2:
                return None
            auth_level = raw_bytes[0]
            if auth_level == 0x02:
                sig_len = 4
                key_name = "visitor"
                key = visitor_key
            elif auth_level == 0x03:
                sig_len = 16
                key_name = "manager"
                key = manager_key
            else:
                return None

            header_len = 1 + sig_len + 2
            if len(raw_bytes) < header_len:
                return None

            sig = raw_bytes[1 : 1 + sig_len]
            cmac_input = raw_bytes[1 + sig_len :]  # seq(2) + payload
            seq = int.from_bytes(cmac_input[:2], byteorder="big", signed=False)
            payload = cmac_input[2:]

            verified: bool | None
            if key is None:
                verified = None
            else:
                try:
                    expected = classic_cmac_prefix(key, self._classicConnHash8, cmac_input, sig_len)
                except Exception:
                    verified = False
                else:
                    verified = expected == sig

            return {
                "mode": "conformant",
                "auth_level": auth_level,
                "sig_len": sig_len,
                "seq": seq,
                "key_name": key_name if key is not None else None,
                "verified": verified,
                "payload": payload,
            }

        def _parse_legacy(raw_bytes: bytes, *, sig_len: int) -> dict[str, Any] | None:
            if len(raw_bytes) < sig_len + 1:
                return None
            sig = raw_bytes[:sig_len]
            payload = raw_bytes[sig_len:]

            # In non-conformant mode Android still selects visitor/manager key for CMAC,
            # but the header contains only the CMAC prefix (typically 4 bytes).
            verified: bool | None = None
            key_name: str | None = None

            keys_to_try: list[tuple[str, bytes | None]] = [
                ("visitor", visitor_key),
                ("manager", manager_key),
            ]
            any_key = any(k is not None for _, k in keys_to_try)
            if any_key:
                verified = False
                for nm, key in keys_to_try:
                    if key is None:
                        continue
                    try:
                        expected = classic_cmac_prefix(key, self._classicConnHash8, payload, sig_len)
                    except Exception:
                        continue
                    if expected == sig:
                        verified = True
                        key_name = nm
                        break

            return {
                "mode": "legacy",
                "auth_level": None,
                "sig_len": sig_len,
                "seq": None,
                "key_name": key_name,
                "verified": verified,
                "payload": payload,
            }

        # Try the currently selected header mode first, then fall back.
        # Some mixed/legacy setups differ between CA52 (legacy) and auth-UUID (conformant).
        parsed_candidates: list[dict[str, Any]] = []
        preferred = self._classicHeaderMode or "conformant"
        if preferred == "legacy":
            for sl in (4, 16):
                r = _parse_legacy(raw, sig_len=sl)
                if r is not None:
                    parsed_candidates.append(r)
            r = _parse_conformant(raw)
            if r is not None:
                parsed_candidates.append(r)
        else:
            r = _parse_conformant(raw)
            if r is not None:
                parsed_candidates.append(r)
            for sl in (4, 16):
                r = _parse_legacy(raw, sig_len=sl)
                if r is not None:
                    parsed_candidates.append(r)

        if not parsed_candidates:
            self._classicRxParseFail += 1
            if self._logLimiter.allow("classic_rx_parse_fail", burst=5, window_s=60.0):
                self._logger.warning(
                    "[CASAMBI_CLASSIC_RX_PARSE_FAIL] len=%d prefix=%s",
                    len(raw),
                    b2a(raw[: min(len(raw), 32)]),
                )
            return

        # Choose best candidate by score; tie-breaker prefers current mode.
        for c in parsed_candidates:
            c["score"] = _score(c["verified"], c["payload"])

        parsed_candidates.sort(
            key=lambda c: (
                c["score"],
                1 if c["mode"] == preferred else 0,
                -c["sig_len"],
            ),
            reverse=True,
        )
        best = parsed_candidates[0]

        if best["score"] == 0:
            self._classicRxParseFail += 1
            if self._logLimiter.allow("classic_rx_unplausible", burst=5, window_s=60.0):
                self._logger.warning(
                    "[CASAMBI_CLASSIC_RX_UNPLAUSIBLE] preferred=%s len=%d prefix=%s",
                    preferred,
                    len(raw),
                    b2a(raw[: min(len(raw), 32)]),
                )
            return

        payload = best["payload"]
        verified = best["verified"]
        if verified is True:
            self._classicRxVerified += 1
        elif verified is None:
            self._classicRxUnverifiable += 1

        # Record RX in diagnostic history
        rx_entry = {
            "timestamp": rx_ts,
            "handle_uuid": handle_uuid,
            "header_mode": best["mode"],
            "verified": verified,
            "auth_level": best["auth_level"],
            "sig_len": best["sig_len"],
            "seq": best["seq"],
            "payload_len": len(payload),
            "raw_hex": b2a(raw).decode("ascii"),
            "payload_hex": b2a(payload).decode("ascii"),
            "score": best["score"],
        }
        self._classicRxHistory.append(rx_entry)
        if len(self._classicRxHistory) > self._classicDiagMaxHistory:
            self._classicRxHistory = self._classicRxHistory[-self._classicDiagMaxHistory:]

        # Enhanced RX parse result log
        self._logger.warning(
            "[CLASSIC_DIAG_RX_PARSE] mode=%s verified=%s auth=%s sig_len=%d seq=%s score=%d payload_len=%d",
            best["mode"],
            verified,
            None if best["auth_level"] is None else f"0x{best['auth_level']:02x}",
            best["sig_len"],
            None if best["seq"] is None else f"0x{best['seq']:04x}",
            best["score"],
            len(payload),
        )

        # Auto-correct header mode if the other format parses much better.
        if best["mode"] != preferred:
            # Only switch if we got a stronger signal (verified or plausible payload with fewer assumptions).
            if best["score"] >= 50 and self._logLimiter.allow("classic_rx_mode_switch", burst=3, window_s=3600.0):
                self._logger.warning(
                    "[CASAMBI_CLASSIC_RX_MODE] switching %s -> %s (score=%d verified=%s sig_len=%d)",
                    preferred,
                    best["mode"],
                    best["score"],
                    verified,
                    best["sig_len"],
                )
            self._classicHeaderMode = best["mode"]

        # Sample RX logs (limited) + periodic stats (limited).
        if self._logLimiter.allow("classic_rx_sample", burst=10, window_s=60.0):
            self._logger.warning(
                "[CASAMBI_CLASSIC_RX] header=%s verified=%s auth=%s sig_len=%d seq=%s payload_prefix=%s",
                best["mode"],
                verified,
                None if best["auth_level"] is None else f"0x{best['auth_level']:02x}",
                best["sig_len"],
                None if best["seq"] is None else f"0x{best['seq']:04x}",
                b2a(payload[: min(len(payload), 32)]),
            )
        now = time.monotonic()
        if (now - self._classicRxLastStatsTs) > 60.0 and self._logLimiter.allow(
            "classic_rx_stats", burst=2, window_s=60.0
        ):
            self._classicRxLastStatsTs = now
            self._logger.warning(
                "[CASAMBI_CLASSIC_RX_STATS] frames=%d verified=%d unverifiable=%d parse_fail=%d header=%s "
                "type6=%d type7=%d type9=%d cmdstream=%d unknown=%d classic_states=%d",
                self._classicRxFrames,
                self._classicRxVerified,
                self._classicRxUnverifiable,
                self._classicRxParseFail,
                self._classicHeaderMode,
                self._classicRxType6,
                self._classicRxType7,
                self._classicRxType9,
                self._classicRxCmdStream,
                self._classicRxUnknown,
                self._classicRxClassicStates,
            )

        # Classic payloads use a completely different format from EVO.
        # Classic: byte 0 is a type indicator (0=netconfig, 255=log, else=unit_id).
        # EVO: byte 0 is a packet type (6=UnitState, 7=Switch, 9=NetConfig).
        # Dispatch Classic through its own parser to avoid misinterpretation.
        if self._protocolMode == ProtocolMode.CLASSIC:
            self._dispatchClassicPayload(payload)
            return

        # If the payload starts with a known EVO packet type, reuse existing parsers.
        packet_type = payload[0]
        if packet_type in (IncommingPacketType.UnitState, IncommingPacketType.SwitchEvent, IncommingPacketType.NetworkConfig):
            kind = f"type{int(packet_type)}"
            if packet_type == IncommingPacketType.UnitState:
                self._classicRxType6 += 1
                kind = "type6_unitstate"
            elif packet_type == IncommingPacketType.SwitchEvent:
                self._classicRxType7 += 1
                kind = "type7_switch"
            else:
                self._classicRxType9 += 1
                kind = "type9_netconf"

            # Emit a few per-kind examples for reverse engineering.
            if self._classicRxKindSamples.get(kind, 0) < 3:
                self._classicRxKindSamples[kind] = self._classicRxKindSamples.get(kind, 0) + 1
                self._logger.warning(
                    "[CASAMBI_CLASSIC_RX_KIND] kind=%s header=%s verified=%s sig_len=%d seq=%s payload_prefix=%s",
                    kind,
                    best["mode"],
                    verified,
                    best["sig_len"],
                    None if best["seq"] is None else f"0x{best['seq']:04x}",
                    b2a(payload[: min(len(payload), 32)]),
                )

            if self._logger.isEnabledFor(logging.DEBUG):
                self._logger.debug(
                    "[CASAMBI_CLASSIC_RX_PAYLOAD] type=%d len=%d hex=%s",
                    packet_type,
                    len(payload),
                    b2a(payload[: min(len(payload), 64)])
                    + (b"..." if len(payload) > 64 else b""),
                )
            if packet_type == IncommingPacketType.UnitState:
                self._parseUnitStates(payload[1:])
            elif packet_type == IncommingPacketType.SwitchEvent:
                self._parseSwitchEvent(payload[1:], None, raw)
            else:
                # ignore network config
                pass
            return

        # Otherwise, attempt to parse a stream of Classic "command" records:
        # record[0] = (len + 239) mod 256, so len = (b0 - 239) & 0xFF.
        pos = 0
        parsed_any = False
        while pos + 2 <= len(payload):
            enc_len = payload[pos]
            rec_len = (enc_len - 239) & 0xFF
            if rec_len < 2 or pos + rec_len > len(payload):
                break
            rec = payload[pos : pos + rec_len]
            pos += rec_len
            parsed_any = True

            typ = rec[1]
            ordinal = typ & 0x3F
            has_div = (typ & 0x40) != 0
            has_target = (typ & 0x80) != 0
            p = 2
            div = rec[p] if has_div and p < len(rec) else None
            if has_div:
                p += 1
            target = rec[p] if has_target and p < len(rec) else None
            if has_target:
                p += 1
            lifetime = rec[p] if p < len(rec) else None
            if lifetime is not None:
                p += 1
            rec_payload = rec[p:] if p <= len(rec) else b""

            if self._logger.isEnabledFor(logging.DEBUG):
                self._logger.debug(
                    "[CASAMBI_CLASSIC_CMD] ord=%d div=%s target=%s lifetime=%s payload=%s",
                    ordinal,
                    div,
                    target,
                    lifetime,
                    b2a(rec_payload),
                )

        if parsed_any:
            self._classicRxCmdStream += 1
            kind = "cmdstream"
        else:
            self._classicRxUnknown += 1
            kind = "unknown"

        if self._classicRxKindSamples.get(kind, 0) < 3:
            self._classicRxKindSamples[kind] = self._classicRxKindSamples.get(kind, 0) + 1
            self._logger.warning(
                "[CASAMBI_CLASSIC_RX_KIND] kind=%s header=%s verified=%s sig_len=%d seq=%s payload_prefix=%s",
                kind,
                best["mode"],
                verified,
                best["sig_len"],
                None if best["seq"] is None else f"0x{best['seq']:04x}",
                b2a(payload[: min(len(payload), 32)]),
            )

        # Any trailing bytes that don't form a full record are logged for analysis.
        if self._logger.isEnabledFor(logging.DEBUG) and pos < len(payload):
            self._logger.debug(
                "[CASAMBI_CLASSIC_CMD_TRAILING] len=%d hex=%s",
                len(payload) - pos,
                b2a(payload[pos:]),
            )

    def _dispatchClassicPayload(self, payload: bytes) -> None:
        """Dispatch a verified Classic payload based on its type indicator.

        Classic payloads (from C1751c.V()) use a different format from EVO:
        - byte 0 == 0: network config data
        - byte 0 == 255: log message
        - otherwise: unit state stream (byte 0 is the first unit_id)
        """
        if not payload:
            return

        first_byte = payload[0]

        # Log full payload for the first 10 Classic payloads regardless of type.
        if self._classicRxClassicStates < 10:
            self._logger.warning(
                "[CASAMBI_CLASSIC_DISPATCH] #%d type_byte=%d len=%d hex=%s",
                self._classicRxClassicStates,
                first_byte,
                len(payload),
                b2a(payload[: min(len(payload), 64)]).decode("ascii")
                + ("..." if len(payload) > 64 else ""),
            )

        if first_byte == 0:
            self._logger.debug("[CASAMBI_CLASSIC_NETCONFIG] len=%d", len(payload))
            return

        if first_byte == 255:
            self._logger.debug("[CASAMBI_CLASSIC_LOG] len=%d", len(payload))
            return

        # Unit state stream: entire payload is passed (first byte is the first unit_id).
        self._classicRxClassicStates += 1
        self._parseClassicUnitStates(payload)

    def _parseClassicUnitStates(self, data: bytes) -> None:
        """Parse Classic unit state records.

        Ground truth: casambi-android C1751c.V() (line 301+).
        Format is completely different from EVO _parseUnitStates:
        - flags lower nibble = state_len (EVO uses a separate byte)
        - flags bit 5 = extra1 present, bit 6 = extra2 present, bit 7 = offline
        - unit_id 0xF0 = command response (skip)
        """
        self._logger.debug("Parsing Classic unit states...")
        if self._logger.isEnabledFor(logging.DEBUG):
            self._logger.debug("[CASAMBI_CLASSIC_STATES_RAW] len=%d hex=%s", len(data), b2a(data))

        pos = 0
        old_pos = 0
        records_parsed = 0
        try:
            while pos + 2 <= len(data):
                unit_id = data[pos]
                flags = data[pos + 1]
                pos += 2

                state_len = flags & 0x0F
                has_extra1 = (flags & 0x20) != 0
                has_extra2 = (flags & 0x40) != 0
                is_offline = (flags & 0x80) != 0

                # 0xF0 = command response record, skip state_len bytes.
                if unit_id == 0xF0:
                    pos += state_len
                    continue

                extra1 = 0
                if has_extra1:
                    if pos >= len(data):
                        break
                    extra1 = data[pos]
                    pos += 1

                extra2 = 0
                if has_extra2:
                    if pos >= len(data):
                        break
                    extra2 = data[pos]
                    pos += 1

                if pos + state_len > len(data):
                    break

                state = data[pos : pos + state_len]
                pos += state_len
                records_parsed += 1

                # Log the first few parsed records at WARNING level for tester visibility.
                if records_parsed <= 10 or self._logger.isEnabledFor(logging.DEBUG):
                    self._logger.warning(
                        "[CASAMBI_CLASSIC_STATE_PARSED] unit=%d flags=0x%02x state_len=%d "
                        "offline=%s extra1=%d extra2=%d state=%s",
                        unit_id,
                        flags,
                        state_len,
                        is_offline,
                        extra1,
                        extra2,
                        b2a(state),
                    )

                online = not is_offline
                # Let Unit.is_on derive actual on/off from state bytes (dimmer, onoff).
                on = True

                self._dataCallback(
                    IncommingPacketType.UnitState,
                    {
                        "id": unit_id,
                        "online": online,
                        "on": on,
                        "state": state,
                        "flags": flags,
                        "prio": 0,
                        "state_len": state_len,
                        "padding_len": 0,
                        "con": None,
                        "sid": None,
                        "extra_byte": extra1,
                        "extra_float": extra1 / 255.0 if extra1 else 0.0,
                    },
                )

                old_pos = pos
        except IndexError:
            self._logger.error(
                "Ran out of data while parsing Classic unit state! Remaining data %s in %s.",
                b2a(data[old_pos:]),
                b2a(data),
            )

        if records_parsed > 0:
            self._logger.debug(
                "[CASAMBI_CLASSIC_STATES_DONE] records=%d remaining=%d",
                records_parsed,
                len(data) - pos,
            )

    def _parseUnitStates(self, data: bytes) -> None:
        # Ground truth: casambi-android `v1.C1775b.V(Q2.h)` parses decrypted packet type=6
        # as a stream of unit state records. Records have optional bytes depending on flags.
        self._logger.debug("Parsing incoming unit states...")
        if self._logger.isEnabledFor(logging.DEBUG):
            self._logger.debug("Incoming unit state: %s", b2a(data))

        pos = 0
        oldPos = 0
        try:
            # Android uses `while (available() >= 4)` as the loop condition.
            while pos <= len(data) - 4:
                unit_id = data[pos]
                flags = data[pos + 1]
                b8 = data[pos + 2]
                state_len = ((b8 >> 4) & 0x0F) + 1
                prio = b8 & 0x0F
                pos += 3

                online = (flags & 0x02) != 0
                on = (flags & 0x01) != 0

                con: int | None = None
                sid: int | None = None

                # Optional bytes, matching Android:
                # - flags&0x04: con (1 byte)
                # - flags&0x08: sid (1 byte)
                # - flags&0x10: extra byte; if missing Android uses 0xFF
                if flags & 0x04:
                    con = data[pos]
                    pos += 1
                if flags & 0x08:
                    sid = data[pos]
                    pos += 1

                if flags & 0x10:
                    extra_byte = data[pos]
                    pos += 1
                else:
                    extra_byte = 0xFF

                state = data[pos : pos + state_len]
                pos += state_len

                padding_len = (flags >> 6) & 0x03
                padding = data[pos : pos + padding_len] if padding_len else b""
                pos += padding_len

                if self._logger.isEnabledFor(logging.DEBUG):
                    self._logger.debug(
                        "[CASAMBI_UNITSTATE_PARSED] unit=%d flags=0x%02x prio=%d online=%s on=%s con=%s sid=%s extra_byte=%d state=%s padding=%s",
                        unit_id,
                        flags,
                        prio,
                        online,
                        on,
                        con,
                        sid,
                        extra_byte,
                        b2a(state),
                        b2a(padding),
                    )

                self._dataCallback(
                    IncommingPacketType.UnitState,
                    {
                        "id": unit_id,
                        "online": online,
                        "on": on,
                        "state": state,
                        # Additional fields for diagnostics/analysis
                        "flags": flags,
                        "prio": prio,
                        "state_len": state_len,
                        "padding_len": padding_len,
                        "con": con,
                        "sid": sid,
                        "extra_byte": extra_byte,
                        "extra_float": extra_byte / 255.0,
                    },
                )

                oldPos = pos
        except IndexError:
            self._logger.error(
                "Ran out of data while parsing unit state! Remaining data %s in %s.",
                b2a(data[oldPos:]),
                b2a(data),
            )

    def _parseSwitchEvent(
        self, data: bytes, packet_seq: int = None, raw_packet: bytes = None
    ) -> None:
        """Parse decrypted packet type=7 payload (INVOCATION stream).

        Ground truth: casambi-android `v1.C1775b.Q(Q2.h)` parses decrypted packet type=7
        as a stream of INVOCATION frames. Switch button events are INVOCATIONs.
        """

        if self._logger.isEnabledFor(logging.DEBUG):
            data_hex = b2a(data)
            self._logger.debug(
                "Parsing incoming switch event packet #%s... Data: %s",
                packet_seq,
                data_hex,
            )
            self._logger.debug(
                "[CASAMBI_SWITCH_PACKET] Full data #%s: hex=%s len=%d",
                packet_seq,
                data_hex,
                len(data),
            )

        events, stats = self._switchDecoder.decode(
            data,
            packet_seq=packet_seq,
            raw_packet=raw_packet,
            arrival_sequence=self._inPacketCount,
        )

        self._logger.debug(
            "[CASAMBI_SWITCH_SUMMARY] packet=%s frames=%d button_frames=%d input_frames=%d ignored=%d emitted=%d suppressed_same_state=%d",
            packet_seq,
            stats.frames_total,
            stats.frames_button,
            stats.frames_input,
            stats.frames_ignored,
            stats.events_emitted,
            stats.events_suppressed_same_state,
        )

        for ev in events:
            # Back-compat alias: older consumers looked for 'flags'
            if "flags" not in ev:
                ev["flags"] = ev.get("invocation_flags")
            self._dataCallback(IncommingPacketType.SwitchEvent, ev)

    def _processSwitchMessage(
        self,
        message_type: int,
        flags: int,
        button: int,
        payload: bytes,
        full_data: bytes,
        start_pos: int,
        packet_seq: int = None,
        raw_packet: bytes = None,
    ) -> None:
        """Process a switch/button message (types 0x08 or 0x10)."""
        if not payload:
            self._logger.error("Switch message has empty payload")
            return

        # Extract unit_id based on message type
        if message_type == 0x10 and len(payload) >= 3:
            # Type 0x10: unit_id is at payload[2]
            unit_id = payload[2]
            extra_data = payload[3:] if len(payload) > 3 else b""
        else:
            # Standard parsing for other message types
            unit_id = payload[0]
            extra_data = b""
            if len(payload) > 2:
                extra_data = payload[2:]

        # Extract action based on message type (action SHOULD be different for press vs release)
        if message_type == 0x10 and len(payload) > 1:
            # Type 0x10: action is at payload[1]
            action = payload[1]
        elif len(payload) > 1:
            # Other types: action is at payload[1]
            action = payload[1]
        else:
            action = None

        event_string = "unknown"

        # Different interpretation based on message type
        if message_type == 0x08:
            # Type 0x08: Use bit 1 of action for press/release
            if action is not None:
                is_release = (action >> 1) & 1
                event_string = "button_release" if is_release else "button_press"
        elif message_type == 0x10:
            # Type 0x10: The state byte is at position 9 (0-indexed) from message start
            # This applies to all units, not just unit 31
            # full_data for type 0x10 is the message data starting from position 0
            state_pos = 9
            if len(full_data) > state_pos:
                state_byte = full_data[state_pos]
                if state_byte == 0x01:
                    event_string = "button_press"
                elif state_byte == 0x02:
                    event_string = "button_release"
                elif state_byte == 0x09:
                    event_string = "button_hold"
                elif state_byte == 0x0C:
                    event_string = "button_release_after_hold"
                else:
                    self._logger.debug(
                        f"Type 0x10: Unknown state byte 0x{state_byte:02x} at message pos {state_pos}"
                    )
                    # Fallback: check if extra_data starts with 0x12 (indicates release)
                    if len(extra_data) >= 1 and extra_data[0] == 0x12:
                        event_string = "button_release"
                    else:
                        event_string = "button_press"
            else:
                # Fallback when message is too short
                if len(extra_data) >= 1 and extra_data[0] == 0x12:
                    event_string = "button_release"
                    self._logger.debug(
                        "Type 0x10: Using extra_data pattern for release detection"
                    )
                else:
                    # Cannot determine state
                    self._logger.warning(
                        f"Type 0x10 message missing state info, unit_id={unit_id}, payload={b2a(payload)}"
                    )
                    event_string = "unknown"

        action_display = f"{action:#04x}" if action is not None else "N/A"

        self._logger.info(
            f"Switch event (type 0x{message_type:02x}): button={button}, unit_id={unit_id}, "
            f"action={action_display} ({event_string}), flags=0x{flags:02x}"
        )

        # Log detailed info about type 0x08 messages (now processed, not filtered)
        if message_type == 0x08:
            self._logger.info(
                f"Type 0x08 event processed: button={button}, unit_id={unit_id}, "
                f"action={action_display}, event={event_string}, flags=0x{flags:02x}"
            )

        self._dataCallback(
            IncommingPacketType.SwitchEvent,
            {
                "message_type": message_type,
                "button": button,
                "unit_id": unit_id,
                "action": action,
                "event": event_string,
                "flags": flags,
                "extra_data": extra_data,
                # packet_sequence is the device-provided sequence number when available
                # (true 32-bit counter from the BLE header), otherwise the local arrival index.
                "packet_sequence": packet_seq,
                # Include the local arrival index for debugging and correlation.
                "arrival_sequence": self._inPacketCount,
                "raw_packet": b2a(raw_packet) if raw_packet else None,
                "decrypted_data": b2a(full_data),
                "message_position": start_pos,
                "payload_hex": b2a(payload),
            },
        )

    async def disconnect(self) -> None:
        self._logger.info("Disconnecting...")

        if self._classicNoRxTask is not None:
            self._classicNoRxTask.cancel()
            self._classicNoRxTask = None

        if self._callbackTask is not None:
            # Cancel and await the background callback task to avoid
            # 'Task was destroyed but it is pending' warnings.
            self._callbackTask.cancel()
            try:
                await self._callbackTask
            except asyncio.CancelledError:
                pass
            except Exception:
                self._logger.debug("Callback task finished with exception during disconnect.", exc_info=True)
            finally:
                self._callbackTask = None

        if self._gattClient is not None and self._gattClient.is_connected:
            try:
                await self._gattClient.disconnect()
            except Exception:
                self._logger.error("Failed to disconnect BleakClient.", exc_info=True)

        self._connectionState = ConnectionState.NONE
        self._logger.info("Disconnected.")

    def getClassicDiagnostics(self) -> dict[str, Any]:
        """Return Classic protocol diagnostic state for external services.

        This method provides a snapshot of Classic protocol state including:
        - Connection parameters (hash, mode, UUIDs)
        - RX/TX statistics
        - Last N TX and RX packets
        - Any detected errors or anomalies

        Safe to call from HA services for dump_classic_diagnostics.
        """
        return {
            "protocol_mode": self._protocolMode.name if self._protocolMode else None,
            "classic_header_mode": self._classicHeaderMode,
            "classic_hash_source": self._classicHashSource,
            "classic_conn_hash8_hex": b2a(self._classicConnHash8).decode("ascii") if self._classicConnHash8 else None,
            "classic_tx_uuid": self._classicTxCharUuid,
            "classic_notify_uuids": sorted(self._classicNotifyCharUuids) if self._classicNotifyCharUuids else [],
            "classic_first_rx_ts": self._classicFirstRxTs,
            "classic_rx_stats": {
                "frames": self._classicRxFrames,
                "verified": self._classicRxVerified,
                "unverifiable": self._classicRxUnverifiable,
                "parse_fail": self._classicRxParseFail,
                "type6_unitstate": self._classicRxType6,
                "type7_switch": self._classicRxType7,
                "type9_netconf": self._classicRxType9,
                "cmdstream": self._classicRxCmdStream,
                "unknown": self._classicRxUnknown,
            },
            "classic_tx_count": len(self._classicTxHistory),
            "classic_rx_count": len(self._classicRxHistory),
            "classic_tx_history": self._classicTxHistory[-20:],  # Last 20
            "classic_rx_history": self._classicRxHistory[-20:],  # Last 20
        }
