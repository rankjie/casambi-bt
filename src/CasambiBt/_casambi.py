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
        payload = bytes([parameterTag]) + parameterData[:31]  # Max 31 bytes of data after tag
        
        # Send using OpCode.SetParameter (26)
        await self._casaClient._send(OpCode.SetParameter, unitId, payload)
    
    async def update_button_config(self, unit_id: int, button_index: int, action_type: str = "control_unit", target_unit_id: int = None) -> None:
        """Update the configuration of a button on a switch unit.
        
        Args:
            unit_id: The ID of the unit with the button/switch
            button_index: The index of the button to configure (0-based)
            action_type: The type of action ("none", "control_unit", "scene", "cycle_modes")
                        - "none": Disable the button (no action)
                        - "control_unit": Control a specific unit (requires target_unit_id)
                        - "scene": Activate a scene
                        - "cycle_modes": Cycle through modes
            target_unit_id: The ID of the target unit (required for control_unit action)
        """
        if not self._casaClient:
            raise RuntimeError("Not connected to network")
        
        # Get the unit
        unit = self.units.get(unit_id)
        if not unit:
            raise ValueError(f"Unit {unit_id} not found")
        
        # Get current switch config
        switch_config = unit.unitConfig.get("switchConfig", {})
        buttons = switch_config.get("buttons", [])
        
        # Ensure we have enough buttons
        while len(buttons) <= button_index:
            buttons.append({})
        
        # Update the button configuration
        button_config = buttons[button_index]
        
        if action_type == "none":
            # Clear the button configuration - button does nothing
            button_config = {}
        elif action_type == "control_unit" and target_unit_id is not None:
            # Configure button to control a specific unit
            button_config["type"] = 0  # ControlUnit type
            button_config["target"] = (target_unit_id << 8) | 1  # Unit target encoding
            button_config["minDimLevel"] = 0.0
        elif action_type == "scene":
            button_config["type"] = 2  # Scene type
            button_config["target"] = target_unit_id if target_unit_id else 1
        elif action_type == "cycle_modes":
            button_config["type"] = 1  # CycleModes type
            button_config["includeOffUnits"] = True
        else:
            raise ValueError(f"Unknown action_type: {action_type}")
        
        # Update the buttons list
        buttons[button_index] = button_config
        switch_config["buttons"] = buttons
        
        # Convert to JSON and then to bytes
        import json
        config_json = json.dumps(switch_config, separators=(',', ':'))
        config_bytes = config_json.encode('utf-8')
        
        # Find the parameter tag for switchConfig
        # Based on Android analysis, switchConfig typically uses a specific tag
        # This may need adjustment based on the actual device
        SWITCH_CONFIG_TAG = 1  # This needs to be determined from the device
        
        # Send the parameter update
        await self.setParameter(unit_id, SWITCH_CONFIG_TAG, config_bytes)
        
        self._logger.info(f"Updated button {button_index} on unit {unit_id} to {action_type} targeting {target_unit_id}")

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
