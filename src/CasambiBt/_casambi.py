import asyncio
import logging
from binascii import b2a_hex as b2a
from collections.abc import Callable
from itertools import pairwise
from pathlib import Path
from typing import Any, cast

from bleak.backends.device import BLEDevice
from httpx import AsyncClient, RequestError

from ._cache import Cache
from ._client import CasambiClient, ConnectionState, IncommingPacketType
from ._network import Network
from ._operation import OpCode, OperationsContext
from ._unit import Group, Scene, Unit, UnitControlType, UnitState
from .errors import ConnectionStateError, ProtocolError


class Casambi:
    """Class to manage one Casambi network.

    This is the central point of interaction and should be preferred to dealing with the internal components,
    e.g. ``Network`` or ``CasambiClient``, directly.
    """

    def __init__(
        self,
        httpClient: AsyncClient | None = None,
        cachePath: Path | None = None,
    ) -> None:
        self._casaClient: CasambiClient | None = None
        self._casaNetwork: Network | None = None

        self._unitChangedCallbacks: list[Callable[[Unit], None]] = []
        self._switchEventCallbacks: list[Callable[[dict[str, Any]], None]] = []
        self._disconnectCallbacks: list[Callable[[], None]] = []

        self._logger = logging.getLogger(__name__)
        self._opContext = OperationsContext()
        self._ownHttpClient = httpClient is None
        self._httpClient = httpClient

        self._cache = Cache(cachePath)

    def _checkNetwork(self) -> None:
        if not self._casaNetwork or not self._casaNetwork._networkRevision:
            raise ConnectionStateError(
                ConnectionState.AUTHENTICATED,
                ConnectionState.NONE,
                "Network information missing.",
            )

    @property
    def networkName(self) -> str:
        self._checkNetwork()
        return self._casaNetwork._networkName  # type: ignore

    @property
    def networkId(self) -> str:
        return self._casaNetwork._id  # type: ignore

    @property
    def units(self) -> list[Unit]:
        """Get the units in the network if connected.

        :return: A list of all units in the network.
        :raises ConnectionStateError: There is no connection to the network.
        """
        self._checkNetwork()
        return self._casaNetwork.units  # type: ignore

    @property
    def groups(self) -> list[Group]:
        """Get the groups in the network if connected.

        :return: A list of all groups in the network.
        :raises ConnectionStateError: There is no connection to the network.
        """
        self._checkNetwork()
        return self._casaNetwork.groups  # type: ignore

    @property
    def scenes(self) -> list[Scene]:
        """Get the scenes of the network if connected.

        :return: A list of all scenes in the network.
        :raises ConnectionStateError: There is no connection to the network.
        """
        self._checkNetwork()
        return self._casaNetwork.scenes  # type: ignore

    @property
    def connected(self) -> bool:
        """Check whether there is an active connection to the network."""
        return (
            self._casaClient is not None
            and self._casaClient._connectionState == ConnectionState.AUTHENTICATED
        )

    @property
    def rawNetworkData(self) -> dict | None:
        """Get the raw network configuration data if available.
        
        :return: The raw network JSON data or None if not connected.
        """
        if self._casaNetwork:
            return self._casaNetwork.rawNetworkData
        return None

    async def connect(
        self,
        addr_or_device: str | BLEDevice,
        password: str,
        forceOffline: bool = False,
    ) -> None:
        """Connect and authenticate to a network.

        :param addr: The MAC address of the network or a BLEDevice. Use `discover` to find the address of a network.
        :param password: The password for the network.
        :param forceOffline: Whether to avoid contacting the casambi servers.
        :raises AuthenticationError: The supplied password is invalid.
        :raises ProtocolError: The network did not follow the expected protocol.
        :raises NetworkNotFoundError: No network was found under the supplied address.
        :raises NetworkOnlineUpdateNeededError: An offline update isn't possible in the current state.
        :raises BluetoothError: An error occurred in the bluetooth stack.
        """

        if isinstance(addr_or_device, BLEDevice):
            addr = addr_or_device.address
        else:
            # Add colons if necessary.
            if ":" not in addr_or_device:
                addr_or_device = ":".join(["".join(p) for p in pairwise(addr)][::2])
            addr = addr_or_device

        self._logger.info(f"Trying to connect to casambi network {addr}...")

        if not self._httpClient:
            self._httpClient = AsyncClient()

        # Retrieve network information
        uuid = addr.replace(":", "").lower()
        await self._cache.setUuid(uuid)
        self._casaNetwork = Network(uuid, self._httpClient, self._cache)
        await self._casaNetwork.load()
        try:
            await self._casaNetwork.logIn(password, forceOffline)
        # TODO: I don't like that this logic is in this class but I couldn't think of a better way.
        except RequestError:
            self._logger.warning(
                "Network error while logging in. Trying to continue offline.",
                exc_info=True,
            )
            forceOffline = True

        await self._casaNetwork.update(forceOffline)

        self._casaClient = CasambiClient(
            addr_or_device,
            self._dataCallback,
            self._disconnectCallback,
            self._casaNetwork,
        )
        await self._connectClient()

    async def _connectClient(self) -> None:
        """Initiate the bluetooth connection."""
        self._casaClient = cast(CasambiClient, self._casaClient)
        await self._casaClient.connect()
        try:
            await self._casaClient.exchangeKey()
            await self._casaClient.authenticate()
        except ProtocolError as e:
            await self._casaClient.disconnect()
            raise e

    async def setUnitState(self, target: Unit, state: UnitState) -> None:
        """Set the state of one unit directly.

        :param target: The targeted unit.
        :param state: The desired state.
        :return: Nothing is returned by this function. To get the new state register a change handler.
        """
        stateBytes = target.getStateAsBytes(state)
        await self._send(target, stateBytes, OpCode.SetState)

    async def setLevel(self, target: Unit | Group | None, level: int) -> None:
        """Set the level (brightness) for one or multiple units.

        If ``target`` is of type ``Unit`` only this unit is affected.
        If ``target`` is of type ``Group`` the whole group is affected.
        if ``target`` is of type ``None`` all units in the network are affected.

        :param target: One or multiple targeted units.
        :param level: The desired level in range [0, 255]. If 0 the unit is turned off.
        :return: Nothing is returned by this function. To get the new state register a change handler.
        :raises ValueError: The supplied level isn't in range
        """
        if level < 0 or level > 255:
            raise ValueError()

        payload = level.to_bytes(1, byteorder="big", signed=False)
        await self._send(target, payload, OpCode.SetLevel)

    async def setVertical(self, target: Unit | Group | None, vertical: int) -> None:
        """Set the vertical (balance between top and bottom LED) for one or multiple units.

        If ``target`` is of type ``Unit`` only this unit is affected.
        If ``target`` is of type ``Group`` the whole group is affected.
        if ``target`` is of type ``None`` all units in the network are affected.

        :param target: One or multiple targeted units.
        :param vertical: The desired vertical balance in range [0, 255]. If 0 the unit is turned off.
        :return: Nothing is returned by this function. To get the new state register a change handler.
        :raises ValueError: The supplied level isn't in range
        """
        if vertical < 0 or vertical > 255:
            raise ValueError()

        payload = vertical.to_bytes(1, byteorder="big", signed=False)
        await self._send(target, payload, OpCode.SetVertical)

    async def setSlider(self, target: Unit | Group | None, value: int) -> None:
        """Set the slider for one or multiple units.

        If ``target`` is of type ``Unit`` only this unit is affected.
        If ``target`` is of type ``Group`` the whole group is affected.
        if ``target`` is of type ``None`` all units in the network are affected.

        :param target: One or multiple targeted units.
        :param value: The desired value in range [0, 255].
        :return: Nothing is returned by this function. To get the new state register a change handler.
        :raises ValueError: The supplied level isn't in range
        """
        if value < 0 or value > 255:
            raise ValueError()

        payload = value.to_bytes(1, byteorder="big", signed=False)
        await self._send(target, payload, OpCode.SetSlider)

    async def setWhite(self, target: Unit | Group | None, level: int) -> None:
        """Set the white level for one or multiple units.

        If ``target`` is of type ``Unit`` only this unit is affected.
        If ``target`` is of type ``Group`` the whole group is affected.
        if ``target`` is of type ``None`` all units in the network are affected.

        :param target: One or multiple targeted units.
        :param level: The desired level in range [0, 255].
        :return: Nothing is returned by this function. To get the new state register a change handler.
        :raises ValueError: The supplied level isn't in range
        """
        if level < 0 or level > 255:
            raise ValueError()

        payload = level.to_bytes(1, byteorder="big", signed=False)
        await self._send(target, payload, OpCode.SetWhite)

    async def setColor(
        self, target: Unit | Group | None, rgbColor: tuple[int, int, int]
    ) -> None:
        """Set the rgb color for one or multiple units.

        If ``target`` is of type ``Unit`` only this unit is affected.
        If ``target`` is of type ``Group`` the whole group is affected.
        if ``target`` is of type ``None`` all units in the network are affected.

        :param target: One or multiple targeted units.
        :param rgbColor: The desired color as a tuple of three ints in range [0, 255].
        :return: Nothing is returned by this function. To get the new state register a change handler.
        :raises ValueError: The supplied rgbColor isn't in range
        """

        state = UnitState()
        state.rgb = rgbColor
        hs: tuple[float, float] = state.hs  # type: ignore[assignment]
        hue = round(hs[0] * 1023)
        sat = round(hs[1] * 255)

        payload = hue.to_bytes(2, byteorder="little", signed=False) + sat.to_bytes(
            1, byteorder="little", signed=False
        )
        await self._send(target, payload, OpCode.SetColor)

    async def setTemperature(
        self, target: Unit | Group | None, temperature: int
    ) -> None:
        """Set the temperature for one or multiple units.

        If ``target`` is of type ``Unit`` only this unit is affected.
        If ``target`` is of type ``Group`` the whole group is affected.
        if ``target`` is of type ``None`` all units in the network are affected.

        :param target: One or multiple targeted units.
        :param temperature: The desired temperature in degrees Kelvin.
        :return: Nothing is returned by this function. To get the new state register a change handler.
        :raises ValueError: The supplied temperature isn't in range
        """

        temperature = int(temperature / 50)
        payload = temperature.to_bytes(1, byteorder="big", signed=False)
        await self._send(target, payload, OpCode.SetTemperature)

    async def setColorXY(
        self, target: Unit | Group | None, xyColor: tuple[float, float]
    ) -> None:
        """Set the xy color for one or multiple units.

        If ``target`` is of type ``Unit`` only this unit is affected.
        If ``target`` is of type ``Group`` the whole group is affected.
        if ``target`` is of type ``None`` all units in the network are affected.

        :param target: One or multiple targeted units.
        :param xyColor: The desired color as a pair of floats in the range [0.0, 1.0].
        :return: Nothing is returned by this function. To get the new state register a change handler.
        :raises ValueError: The supplied XYColor isn't in range or not supported by the supplied unit.
        """

        if xyColor[0] < 0.0 or xyColor[0] > 1.0 or xyColor[1] < 0.0 or xyColor[1] > 1.0:
            raise ValueError("Color out of range.")

        # We assume a default length of 22 bits, so 11 bits per coordinate. Is this sane?
        coordLen = 11
        if target is not None and isinstance(target, Unit):
            control = target.unitType.get_control(UnitControlType.XY)
            if control is None:
                raise ValueError("The control isn't supported by this unit.")
            coordLen = control.length // 2
        mask = (1 << coordLen) - 1
        x = round(xyColor[0] * mask) & mask
        y = round(xyColor[1] * mask) & mask

        payload = ((x << coordLen) | y).to_bytes(3, byteorder="little", signed=False)
        await self._send(target, payload, OpCode.SetColorXY)

    async def turnOn(self, target: Unit | Group | None) -> None:
        """Turn one or multiple units on to their last level.

        If ``target`` is of type ``Unit`` only this unit is affected.
        If ``target`` is of type ``Group`` the whole group is affected.
        if ``target`` is of type ``None`` all units in the network are affected.

        :param target: One or multiple targeted units.
        :return: Nothing is returned by this function. To get the new state register a change handler.
        """

        # Use -1 to indicate special packet format
        # Use RestoreLastLevel flag (1) and UseFullTimeFlag (4).
        # Not sure what UseFullTime does but this is what the app uses.
        await self._send(target, b"\xff\x05", OpCode.SetLevel)

    async def switchToScene(self, target: Scene, level: int = 0xFF) -> None:
        """Switch the network to a predefined scene.

        :param target: The scene to switch to.
        :param level: An optional relative brightness for all units in the scene.
        :return: Nothing is returned by this function. To get the new state register a change handler.
        """
        await self.setLevel(target, level)  # type: ignore[arg-type]

    async def _send(
        self, target: Unit | Group | Scene | None, state: bytes, opcode: OpCode
    ) -> None:
        if self._casaClient is None:
            raise ConnectionStateError(
                ConnectionState.AUTHENTICATED,
                ConnectionState.NONE,
            )

        targetCode = 0
        if isinstance(target, Unit):
            assert target.deviceId <= 0xFF
            targetCode = (target.deviceId << 8) | 0x01
        elif isinstance(target, Group):
            assert target.groudId <= 0xFF
            targetCode = (target.groudId << 8) | 0x02
        elif isinstance(target, Scene):
            assert target.sceneId <= 0xFF
            targetCode = (target.sceneId << 8) | 0x04
        elif target is not None:
            raise TypeError(f"Unkown target type {type(target)}")

        self._logger.debug(
            f"Sending operation {opcode.name} with payload {b2a(state)} for {targetCode:x}"
        )

        opPkt = self._opContext.prepareOperation(opcode, targetCode, state)

        try:
            await self._casaClient.send(opPkt)
        except ConnectionStateError as exc:
            if exc.got == ConnectionState.NONE:
                self._logger.info("Trying to reconnect broken connection once.")
                await self._connectClient()
                await self._casaClient.send(opPkt)
            else:
                raise exc

    def _dataCallback(
        self, packetType: IncommingPacketType, data: dict[str, Any]
    ) -> None:
        self._logger.info(f"Incomming data callback of type {packetType}")
        if packetType == IncommingPacketType.UnitState:
            self._logger.debug(
                f"Handling changed state {b2a(data['state'])} for unit {data['id']}"
            )

            found = False
            for u in self._casaNetwork.units:  # type: ignore[union-attr]
                if u.deviceId == data["id"]:
                    found = True
                    u.setStateFromBytes(data["state"])
                    u._on = data["on"]
                    u._online = data["online"]

                    # Notify listeners
                    for h in self._unitChangedCallbacks:
                        try:
                            h(u)
                        except Exception:
                            self._logger.error(
                                f"Exception occurred in unitChangedCallback {h}.",
                                exc_info=True,
                            )

            if not found:
                self._logger.error(
                    f"Changed state notification for unkown unit {data['id']}"
                )
        elif packetType == IncommingPacketType.SwitchEvent:
            self._logger.debug(
                f"Handling switch event: unit_id={data.get('unit_id')}, "
                f"button={data.get('button')}, event={data.get('event')}"
            )

            # Notify listeners
            for switch_handler in self._switchEventCallbacks:
                try:
                    switch_handler(data)
                except Exception:
                    self._logger.error(
                        f"Exception occurred in switchEventCallback {switch_handler}.",
                        exc_info=True,
                    )
        else:
            self._logger.warning(f"Handler for type {packetType} not implemented!")

    def registerUnitChangedHandler(self, handler: Callable[[Unit], None]) -> None:
        """Register a new handler for unit state changed.

        This handler is called whenever a new state for a unit is received.
        The handler is supplied by the unit for which the state changed
        and the state property of the unit is set to the new state.

        :param handler: The method to call when a new unit state is received.
        """
        self._unitChangedCallbacks.append(handler)
        self._logger.debug(f"Registered unit changed handler {handler}")

    def unregisterUnitChangedHandler(self, handler: Callable[[Unit], None]) -> None:
        """Unregister an existing unit state change handler.

        :param handler: The handler to unregister.
        :raises ValueError: If the handler isn't registered.
        """
        self._unitChangedCallbacks.remove(handler)
        self._logger.debug(f"Removed unit changed handler {handler}")

    def registerSwitchEventHandler(
        self, handler: Callable[[dict[str, Any]], None]
    ) -> None:
        """Register a new handler for switch events.

        This handler is called whenever a switch event is received.
        The handler is supplied with a dictionary containing:
        - unit_id: The ID of the switch unit
        - button: The button number that was pressed/released
        - event: Either "button_press" or "button_release"
        - message_type: The raw message type (0x08 or 0x10)
        - flags: Additional flags from the message
        - extra_data: Any additional data from the message

        :param handler: The method to call when a switch event is received.
        """
        self._switchEventCallbacks.append(handler)
        self._logger.debug(f"Registered switch event handler {handler}")

    def unregisterSwitchEventHandler(
        self, handler: Callable[[dict[str, Any]], None]
    ) -> None:
        """Unregister an existing switch event handler.

        :param handler: The handler to unregister.
        :raises ValueError: If the handler isn't registered.
        """
        self._switchEventCallbacks.remove(handler)
        self._logger.debug(f"Removed switch event handler {handler}")

    def registerDisconnectCallback(self, callback: Callable[[], None]) -> None:
        """Register a disconnect callback.

        The callback is called whenever the Bluetooth stack reports that
        the Bluetooth connection to the network was disconnected.

        :params callback: The callback to register.
        """
        self._disconnectCallbacks.append(callback)
        self._logger.debug(f"Registered disconnect callback {callback}")

    def unregisterDisconnectCallback(self, callback: Callable[[], None]) -> None:
        """Unregister an existing disconnect callback.

        :param callback: The callback to unregister.
        :raises ValueError: If the callback isn't registered.
        """
        self._disconnectCallbacks.remove(callback)
        self._logger.debug(f"Removed disconnect callback {callback}")

    async def invalidateCache(self, uuid: str) -> None:
        """Invalidates the cache for a network.

        :param uuid: The address of the network.
        """

        # We can't use our own cache here since the invalidation happens
        # before the first connection attempt.
        tempCache = Cache(self._cache._cachePath)
        await tempCache.setUuid(uuid)
        await tempCache.invalidateCache()

    def _disconnectCallback(self) -> None:
        # Mark all units as offline on disconnect.
        for u in self.units:
            u._online = False
            for h in self._unitChangedCallbacks:
                try:
                    h(u)
                except Exception:
                    self._logger.error(
                        f"Exception occurred in unitChangedHandler {h}.",
                        exc_info=True,
                    )

        for d in self._disconnectCallbacks:
            try:
                d()
            except Exception:
                self._logger.error(
                    f"Exception occurred in disconnectCallback {d}.",
                    exc_info=True,
                )

    async def setParameter(self, unitId: int, parameterTag: int, parameterData: bytes) -> None:
        """Send a SetParameter command to a unit.
        
        Args:
            unitId: The ID of the unit to send the command to
            parameterTag: The parameter tag/ID to update
            parameterData: The raw parameter data to send
        """
        if not self._casaClient:
            raise RuntimeError("Not connected to network")
        
        # Build payload: [parameter_tag][parameter_data]
        # Note: SetParameter supports max 31 bytes after the tag.
        payload = bytes([parameterTag]) + parameterData[:31]
        
        # Send using OpCode.SetParameter (26)
        opPkt = self._opContext.prepareOperation(OpCode.SetParameter, (unitId << 8) | 0x01, payload)
        await self._casaClient.send(opPkt)

    async def send_ext_packet(self, unit_id: int, seq: int, chunk: bytes, *, lifetime: int = 9) -> None:
        """Send an extended packet (ExtPacketSend / opcode 43) to a unit.

        Payload is framed as: [0x29][seq][chunk...]

        Notes:
        - Total payload must be <= 63 bytes, so len(chunk) <= 61.
        - Lifetime defaults to 9 to mirror longer-running multi-chunk ops seen on Android.
        """
        if not self._casaClient:
            raise RuntimeError("Not connected to network")

        if seq < 0 or seq > 255:
            raise ValueError("seq must be 0..255")
        if len(chunk) > 61:
            raise ValueError("chunk too large; max 61 bytes to fit ExtPacket payload")

        payload = bytes([0x29, seq & 0xFF]) + chunk
        target = (int(unit_id) << 8) | 0x01
        opPkt = self._opContext.prepareOperation(
            OpCode.ExtPacketSend,
            target,
            payload,
            lifetime=lifetime,
        )
        await self._casaClient.send(opPkt)

    async def start_switch_session(self, unit_id: int, *, payload: bytes = b"", lifetime: int = 9) -> None:
        """Experimental: send AcquireSwitchSession (opcode 42).

        Payload is device-specific and currently unknown for switchConfig; by default
        sends an empty payload. Use for experimentation only until framing is confirmed.
        """
        if not self._casaClient:
            raise RuntimeError("Not connected to network")
        if len(payload) > 63:
            raise ValueError("payload too large; max 63 bytes")
        target = (int(unit_id) << 8) | 0x01
        opPkt = self._opContext.prepareOperation(
            OpCode.AcquireSwitchSession,
            target,
            payload,
            lifetime=lifetime,
        )
        await self._casaClient.send(opPkt)

    async def apply_switch_config_ble(self, unit_id: int, *, parameter_tag: int | None = None) -> None:
        """Attempt to push the unit's switchConfig to the device over BLE.

        This method currently supports only very small configurations that fit
        into a single SetParameter payload (max 31 bytes after the tag).

        Args:
            unit_id: The ID of the unit to update.
            parameter_tag: Optional override for the parameter tag; if not provided,
                           a default of 1 is used (subject to device variation).

        Raises:
            RuntimeError: If not connected or no raw network data.
            ValueError: If the encoded switchConfig is too large for SetParameter.
        """
        if not self._casaClient:
            raise RuntimeError("Not connected to network")
        if not self._casaNetwork or not self._casaNetwork.rawNetworkData:
            raise RuntimeError("No raw network data available; connect and update first")

        units = self._casaNetwork.rawNetworkData.get("network", {}).get("units", [])
        unit_data = next((u for u in units if u.get("deviceID") == unit_id), None)
        if not unit_data:
            raise ValueError(f"Unit {unit_id} not found in raw network data")

        switch_config = unit_data.get("switchConfig") or {}

        import json
        config_bytes = json.dumps(switch_config, separators=(",", ":")).encode("utf-8")

        # Protocol restriction: SetParameter accepts max 31 bytes after tag.
        if len(config_bytes) > 31:
            raise ValueError(
                "switchConfig exceeds 31 bytes; multi-packet BLE apply is required. "
                "This library will need an extended writer (AcquireSwitchSession/ExtPacketSend) to support large configs."
            )

        tag = 1 if parameter_tag is None else int(parameter_tag)
        await self.setParameter(unit_id, tag, config_bytes)
        self._logger.info(
            "Applied switchConfig via SetParameter (tag=%s, bytes=%s) for unit %s",
            tag,
            len(config_bytes),
            unit_id,
        )

    async def apply_switch_config_ble_large(self, unit_id: int) -> None:
        """Experimental: attempt to push switchConfig using ExtPacketSend in chunks.

        WARNING: Framing is not fully confirmed for switchConfig updates. This method
        sends raw JSON bytes chunked as consecutive ExtPacket frames with header
        [0x29][seq]. Use only for experimentation and logs; correctness is not guaranteed.
        """
        if not self._casaClient:
            raise RuntimeError("Not connected to network")
        if not self._casaNetwork or not self._casaNetwork.rawNetworkData:
            raise RuntimeError("No raw network data available; connect and update first")

        units = self._casaNetwork.rawNetworkData.get("network", {}).get("units", [])
        unit_data = next((u for u in units if u.get("deviceID") == unit_id), None)
        if not unit_data:
            raise ValueError(f"Unit {unit_id} not found in raw network data")

        switch_config = unit_data.get("switchConfig") or {}
        import json
        data = json.dumps(switch_config, separators=(",", ":")).encode("utf-8")

        # Attempt to start a switch session before sending chunks. Some devices
        # expect an AcquireSwitchSession (opcode 42) handshake prior to ExtPacketSend.
        try:
            await self.start_switch_session(unit_id)
            self._logger.info("Started switch session (AcquireSwitchSession) for unit %s", unit_id)
        except Exception as e:
            # Non-fatal: proceed without session if device doesn't require it.
            self._logger.info(
                "AcquireSwitchSession not acknowledged or unsupported for unit %s (%s); proceeding with ExtPacketSend only.",
                unit_id,
                e,
            )

        # Chunk into 61-byte pieces (ExtPacket payload allows 63 total minus 2-byte header)
        max_chunk = 61
        seq = 0
        for off in range(0, len(data), max_chunk):
            chunk = data[off : off + max_chunk]
            await self.send_ext_packet(unit_id, seq, chunk, lifetime=9)
            self._logger.debug(
                "ExtPacket chunk sent: unit=%s seq=%s size=%s/%s", unit_id, seq, len(chunk), len(data)
            )
            seq = (seq + 1) & 0xFF
        self._logger.info(
            "ExtPacket switchConfig attempt complete (unit=%s, total_bytes=%s, chunks=%s)",
            unit_id,
            len(data),
            (len(data) + max_chunk - 1) // max_chunk,
        )

    async def update_button_config(
        self,
        unit_id: int,
        button_index: int,
        action_type: str,
        target_id: int | None = None,
        *,
        exclusive_scenes: bool | None = None,
        long_press_all_off: bool | None = None,
        toggle_disabled: bool | None = None,
    ) -> dict:
        """Update one button entry in a unit's switchConfig in the cached network data.

        Android mapping for actions (EnumC0105q):
        - none -> 0, target 0
        - scene -> 1, target=sceneID
        - control_unit -> 2, target=deviceID
        - control_group -> 3, target=groupID
        - all_units -> 4, target=255
        - resume_automation -> 6, target=0
        - resume_automation_group -> 7, target=groupID

        Returns the updated switchConfig dict.
        """
        if button_index < 0 or button_index > 7:
            raise ValueError("button_index must be in range 0..7")

        raw = self.rawNetworkData
        if not raw:
            raise RuntimeError("No raw network data loaded. Connect and update first.")

        # Locate the unit's JSON entry
        units = raw.get("network", {}).get("units", [])
        unit_data = None
        for u in units:
            if u.get("deviceID") == unit_id:
                unit_data = u
                break
        if not unit_data:
            raise ValueError(f"Unit {unit_id} not found in raw network data")

        switch_config = unit_data.get("switchConfig") or {}
        buttons: list[dict] = switch_config.get("buttons") or []

        action_map = {
            "none": 0,
            "scene": 1,
            "control_unit": 2,
            "control_group": 3,
            "all_units": 4,
            "resume_automation": 6,
            "resume_automation_group": 7,
        }
        if action_type not in action_map:
            raise ValueError(
                "Unsupported action_type. Use one of: none, scene, control_unit, "
                "control_group, all_units, resume_automation, resume_automation_group"
            )
        action_code = action_map[action_type]

        if action_type == "all_units":
            resolved_target = 255
        elif action_type in ("none", "resume_automation"):
            resolved_target = 0
        else:
            if target_id is None:
                raise ValueError(f"target_id is required for action_type '{action_type}'")
            resolved_target = int(target_id)

        # Find or create entry for this button index
        existing = None
        for b in buttons:
            if b.get("type") == button_index:
                existing = b
                break
        entry = existing or {"type": button_index, "action": 0, "target": 0}
        entry["action"] = action_code
        entry["target"] = resolved_target
        if not existing:
            buttons.append(entry)

        # Persist and apply optional flags
        switch_config["buttons"] = buttons
        if exclusive_scenes is not None:
            switch_config["exclusiveScenes"] = bool(exclusive_scenes)
        if long_press_all_off is not None:
            switch_config["longPressAllOff"] = bool(long_press_all_off)
        if toggle_disabled is not None:
            switch_config["toggleDisabled"] = bool(toggle_disabled)

        unit_data["switchConfig"] = switch_config

        self._logger.info(
            "Updated switchConfig (unit=%s, button=%s, action=%s, target=%s)",
            unit_id,
            button_index,
            action_type,
            resolved_target,
        )

        return switch_config

    async def disconnect(self) -> None:
        """Disconnect from the network."""
        if self._casaClient:
            try:
                await asyncio.shield(self._casaClient.disconnect())
            except Exception:
                self._logger.error("Failed to disconnect from client.", exc_info=True)
        if self._casaNetwork:
            try:
                await asyncio.shield(self._casaNetwork.disconnect())
            except Exception:
                self._logger.error("Failed to disconnect from network.", exc_info=True)
            self._casaNetwork = None
        if self._ownHttpClient and self._httpClient is not None:
            try:
                await asyncio.shield(self._httpClient.aclose())
            except Exception:
                self._logger.error("Failed to close http client.", exc_info=True)
