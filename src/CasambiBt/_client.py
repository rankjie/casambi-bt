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
from ._constants import CASA_CLASSIC_DATA_CHAR_UUID, CASA_CLASSIC_HASH_CHAR_UUID
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

        # Rate limit WARNING logs (especially Classic RX) to keep HA usable.
        self._logLimiter = _LogBurstLimiter()
        self._classicRxFrames = 0
        self._classicRxVerified = 0
        self._classicRxUnverifiable = 0
        self._classicRxParseFail = 0
        self._classicRxLastStatsTs = time.monotonic()

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
        auth_prefix: bytes | None = None
        auth_err: str | None = None
        device_nodeinfo_protocol: int | None = None

        def _log_probe_summary(mode: str) -> None:
            # One stable, high-signal line for testers.
            self._logger.warning(
                "[CASAMBI_PROTOCOL_PROBE] address=%s mode=%s cloud_protocol=%s nodeinfo_b1=%s "
                "data_uuid=%s classic_hash8_present=%s auth_read_prefix=%s ca51_read_prefix=%s ca51_read_error=%s auth_read_error=%s",
                self.address,
                mode,
                cloud_protocol,
                device_nodeinfo_protocol,
                self._dataCharUuid,
                bool(classic_hash and len(classic_hash) >= 8),
                auth_prefix,
                ca51_prefix,
                ca51_err,
                auth_err,
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
            self._classicHeaderMode = "legacy"

            # Read connection hash (first 8 bytes are used for CMAC signing).
            raw_hash = classic_hash
            if raw_hash is None or len(raw_hash) < 8:
                raise ClassicHandshakeError(
                    f"Classic connection hash read failed/too short (len={0 if raw_hash is None else len(raw_hash)})."
                )
            self._classicConnHash8 = bytes(raw_hash[:8])
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
                # continue detection below
            else:
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
                _log_probe_summary("CLASSIC")
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
            self._classicHeaderMode = "conformant"
            self._classicConnHash8 = bytes(first[:8])
            self._classicCmdDiv = int.from_bytes(os.urandom(1), "big") or 1
            self._classicTxSeq = 0

            notify_kwargs: dict[str, Any] = {}
            notify_params = inspect.signature(self._gattClient.start_notify).parameters
            if "bluez" in notify_params:
                notify_kwargs["bluez"] = {"use_start_notify": True}
            await self._gattClient.start_notify(
                CASA_AUTH_CHAR_UUID,
                self._queueCallback,
                **notify_kwargs,
            )
            self._connectionState = ConnectionState.AUTHENTICATED
            self._logger.info("Protocol mode selected: CLASSIC")
            if self._logger.isEnabledFor(logging.DEBUG):
                self._logger.debug("[CASAMBI_GATT_PROBE] start_notify auth ok (classic conformant)")
                self._logger.debug(
                    "[CASAMBI_CLASSIC_CONN_HASH] len=%d hash=%s",
                    len(self._classicConnHash8),
                    b2a(self._classicConnHash8),
                )
            _log_probe_summary("CLASSIC")
            return

        _log_probe_summary("UNKNOWN")
        raise ProtocolError(
            "No supported Casambi characteristics found (Classic ca51/ca52 or EVO/Classic-conformant auth char)."
        )

    def _on_disconnect(self, client: BleakClient) -> None:
        if self._connectionState != ConnectionState.NONE:
            self._logger.info(f"Received disconnect callback from {self.address}")
        if self._connectionState == ConnectionState.AUTHENTICATED:
            self._logger.debug("Executing disconnect callback.")
            self._disconnectedCallback()
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

    async def _sendClassic(self, command_bytes: bytes) -> None:
        self._checkState(ConnectionState.AUTHENTICATED)
        if self._protocolMode != ProtocolMode.CLASSIC:
            raise ProtocolError("Classic send called while not in Classic protocol mode.")
        if not self._dataCharUuid:
            raise ProtocolError("Classic data characteristic UUID not set.")
        if self._classicConnHash8 is None:
            raise ClassicHandshakeError("Classic connection hash not available.")

        visitor_key = self._network.classicVisitorKey()
        manager_key = self._network.classicManagerKey()

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

        # WARNING-level TX logs are intentional: they are needed for Classic reverse engineering.
        # Keep payload logging minimal (prefix only).
        if self._logLimiter.allow("classic_tx", burst=50, window_s=60.0):
            self._logger.warning(
                "[CASAMBI_CLASSIC_TX] header=%s key=%s auth=0x%02x sig_len=%d seq=%s cmd_len=%d total_len=%d prefix=%s",
                header_mode,
                key_name,
                auth_level,
                sig_len,
                None if seq is None else f"0x{seq:04x}",
                len(command_bytes),
                len(pkt),
                b2a(bytes(pkt[: min(len(pkt), 24)])),
            )

        # Classic packets can exceed 20 bytes when using a 16-byte manager signature.
        # Bleak needs a write-with-response for long writes on most backends.
        await self._gattClient.write_gatt_char(self._dataCharUuid, bytes(pkt), response=True)

    def _establishedNofityCallback(
        self, handle: BleakGATTCharacteristic, data: bytes
    ) -> None:
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

        raw = bytes(data)
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
                "[CASAMBI_CLASSIC_RX_STATS] frames=%d verified=%d unverifiable=%d parse_fail=%d header=%s",
                self._classicRxFrames,
                self._classicRxVerified,
                self._classicRxUnverifiable,
                self._classicRxParseFail,
                self._classicHeaderMode,
            )

        # If the payload starts with a known EVO packet type, reuse existing parsers.
        packet_type = payload[0]
        if packet_type in (IncommingPacketType.UnitState, IncommingPacketType.SwitchEvent, IncommingPacketType.NetworkConfig):
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
        while pos + 2 <= len(payload):
            enc_len = payload[pos]
            rec_len = (enc_len - 239) & 0xFF
            if rec_len < 2 or pos + rec_len > len(payload):
                break
            rec = payload[pos : pos + rec_len]
            pos += rec_len

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

        # Any trailing bytes that don't form a full record are logged for analysis.
        if self._logger.isEnabledFor(logging.DEBUG) and pos < len(payload):
            self._logger.debug(
                "[CASAMBI_CLASSIC_CMD_TRAILING] len=%d hex=%s",
                len(payload) - pos,
                b2a(payload[pos:]),
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
