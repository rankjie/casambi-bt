import logging
import os
from binascii import b2a_hex as b2a
from colorsys import hsv_to_rgb, rgb_to_hsv
from dataclasses import dataclass
from enum import Enum, unique
from typing import Any, Final

_LOGGER = logging.getLogger(__name__)


# Numbers are totally arbitrary so far.
@unique
class UnitControlType(Enum):
    """All implemented control types."""

    DIMMER = 0
    """The brightness of the light can be adjusted."""

    WHITE = 1
    """The amount of white in the light can be adjusted."""

    RGB = 2
    """The color of the light can be adjusted."""

    ONOFF = 3
    """The unit can be turned on or off."""

    TEMPERATURE = 4
    """The temperature of the light can be adjusted."""

    VERTICAL = 5
    """The vertical value of the light can be adjusted."""

    COLORSOURCE = 6
    """The light can switch color source. (TW, RGB, XY)"""

    XY = 7
    """The color of the light can be controlled using CIE color space."""

    SLIDER = 8
    """The slider of the light can be adjusted."""

    SENSOR = 9
    """A sensor value of the light."""

    UNKOWN = 99
    """State isn't implemented. Control saved for debuggin purposes."""


@unique
class ColorSource(Enum):
    """The possible values for the color source control."""

    TEMPERATURE = 0
    RGB = 1
    XY = 2


@dataclass(frozen=True, repr=True)
class UnitControl:
    type: UnitControlType
    offset: int
    length: int
    default: int
    readonly: bool

    min: int | None = None
    max: int | None = None


@dataclass(frozen=True, repr=True)
class UnitType:
    """Each ``Unit`` has one type that describes what the model is capable of.

    :ivar model: The model name of this unit type.
    :ivar manufacturer: The manufacturer of this unit type.
    :ivar controls: The different types of controls this unit type is capable of.
    """

    id: int
    model: str
    manufacturer: str
    mode: str
    stateLength: int
    controls: list[UnitControl]

    def get_control(self, controlType: UnitControlType) -> UnitControl | None:
        """Return the control description if the unit type supports the given type of control.

        :param controlType: The desired control type.
        :return: A control description for the given control type if available, otherwise `None`
        """
        for c in self.controls:
            if c.type == controlType:
                return c

        return None


# TODO: Support for different resolutions?
# TODO: Work with HS instead of RGB internally
class UnitState:
    """Parsed representation of the state of a unit."""

    def __init__(self) -> None:
        self._dimmer: int | None = None
        self._rgb: tuple[int, int, int] | None = None
        self._white: int | None = None
        self._temperature: int | None = None
        self._vertical: int | None = None
        self._colorsource: ColorSource | None = None
        self._xy: tuple[float, float] | None = None
        self._slider: int | None = None
        self._onoff: bool | None = None
        # Last raw state bytes, as received from the network.
        self._raw_state: bytes | None = None
        # Unknown controls that we don't have semantic parsing for yet.
        # Items are (offset_bits, length_bits, value_int).
        self._unknown_controls: list[tuple[int, int, int]] = []

    @property
    def raw_state(self) -> bytes | None:
        return self._raw_state

    @property
    def unknown_controls(self) -> list[tuple[int, int, int]]:
        # Expose a copy so callers can't mutate internal tracking.
        return list(self._unknown_controls)

    def as_dict(self) -> dict[str, Any]:
        """Return a stable, JSON-friendly representation for diagnostics."""
        return {
            "dimmer": self.dimmer,
            "vertical": self.vertical,
            "rgb": self.rgb,
            "white": self.white,
            "temperature": self.temperature,
            "colorsource": self.colorsource.name if self.colorsource is not None else None,
            "xy": self.xy,
            "slider": self.slider,
            "onoff": self.onoff,
            "raw_state_hex": b2a(self._raw_state).decode("ascii") if self._raw_state is not None else None,
            "unknown_controls": [
                {"offset": off, "length": length, "value": val}
                for (off, length, val) in self._unknown_controls
            ],
        }

    def _check_range(
        self, value: int | float, min: int | float, max: int | float
    ) -> None:
        if value < min or value > max:
            raise ValueError(f"{value} is not between {min} and {max}")

    DIMMER_RESOLUTION: Final = 8
    DIMMER_MIN: Final = 0
    DIMMER_MAX: Final = 2**DIMMER_RESOLUTION - 1

    @property
    def dimmer(self) -> int | None:
        return self._dimmer

    @dimmer.setter
    def dimmer(self, value: int) -> None:
        self._check_range(value, self.DIMMER_MIN, self.DIMMER_MAX)
        self._dimmer = value

    @dimmer.deleter
    def dimmer(self) -> None:
        self._dimmer = None

    VERTICAL_RESOLUTION: Final = 8
    VERTICAL_MIN: Final = 0
    VERTICAL_MAX: Final = 2**VERTICAL_RESOLUTION - 1

    @property
    def vertical(self) -> int | None:
        return self._vertical

    @vertical.setter
    def vertical(self, value: int) -> None:
        self._check_range(value, self.VERTICAL_MIN, self.VERTICAL_MAX)
        self._vertical = value

    @vertical.deleter
    def vertical(self) -> None:
        self._vertical = None

    RGB_RESOLUTION: Final = 8
    RGB_MIN: Final = 0
    RGB_MAX: Final = 2**RGB_RESOLUTION - 1

    @property
    def rgb(self) -> tuple[int, int, int] | None:
        return self._rgb

    @rgb.setter
    def rgb(self, value: tuple[int, int, int]) -> None:
        r, g, b = value
        self._check_range(r, self.RGB_MIN, self.RGB_MAX)
        self._check_range(g, self.RGB_MIN, self.RGB_MAX)
        self._check_range(b, self.RGB_MIN, self.RGB_MAX)

        self._rgb = (r, g, b)

    @rgb.deleter
    def rgb(self) -> None:
        self._rgb = None

    @property
    def hs(self) -> tuple[float, float] | None:
        """Convert RGB into HS where H is a float in [0..1[ and S a float in [0..1]."""
        if self._rgb is None:
            return None

        rgb_float = [c / (2**self.RGB_RESOLUTION - 1) for c in self._rgb]
        h, s, _ = rgb_to_hsv(*rgb_float)

        h %= 1
        if h == 0 and s == 0:
            h = 0.5

        return (h, s)

    @hs.setter
    def hs(self, value: tuple[float, float]) -> None:
        """Convert HS color to interal RBG representation where H is a float in [0..1[ and S a float in [0..1]."""
        h, s = value

        rgb = hsv_to_rgb(h, s, 1)
        self.rgb = tuple([round(c * (2**self.RGB_RESOLUTION - 1)) for c in rgb])  # type: ignore[assignment]

    WHITE_RESOLUTION = 8
    WHITE_MIN = 0
    WHITE_MAX = 2**WHITE_RESOLUTION - 1

    @property
    def white(self) -> int | None:
        return self._white

    @white.setter
    def white(self, value: int) -> None:
        self._check_range(value, self.WHITE_MIN, self.WHITE_MAX)
        self._white = value

    @white.deleter
    def white(self) -> None:
        self._white = None

    @property
    def temperature(self) -> int | None:
        return self._temperature

    @temperature.setter
    def temperature(self, value: int) -> None:
        self._temperature = value

    @temperature.deleter
    def temperature(self) -> None:
        self.temperature = None

    @property
    def colorsource(self) -> ColorSource | None:
        return self._colorsource

    @colorsource.setter
    def colorsource(self, value: ColorSource) -> None:
        self._colorsource = value

    @colorsource.deleter
    def colorsource(self) -> None:
        self._colorsource = None

    @property
    def xy(self) -> tuple[float, float] | None:
        return self._xy

    @xy.setter
    def xy(self, value: tuple[float, float]) -> None:
        x, y = value
        self._check_range(x, 0, 1)
        self._check_range(y, 0, 1)
        self._xy = (x, y)

    @xy.deleter
    def xy(self) -> None:
        self._xy = None

    SLIDER_RESOLUTION: Final = 8
    SLIDER_MIN: Final = 0
    SLIDER_MAX: Final = 2**VERTICAL_RESOLUTION - 1

    @property
    def slider(self) -> int | None:
        return self._slider

    @slider.setter
    def slider(self, value: int) -> None:
        self._check_range(value, self.SLIDER_MIN, self.SLIDER_MAX)
        self._slider = value

    @slider.deleter
    def slider(self) -> None:
        self.slider = None

    @property
    def onoff(self) -> bool | None:
        return self._onoff

    @onoff.setter
    def onoff(self, value: bool) -> None:
        self._onoff = value

    @onoff.deleter
    def onoff(self) -> None:
        self._onoff = None

    def __repr__(self) -> str:
        return f"UnitState(dimmer={self.dimmer}, vertical={self._vertical}, rgb={self.rgb.__repr__()}, white={self.white}, temperature={self.temperature}, colorsource={self.colorsource}, xy={self.xy}, slider={self.slider}, onoff={self.onoff})"

# TODO: Make unit immutable (refactor state, on, online out of it)
@dataclass(init=True, repr=True)
class Unit:
    """A unit in a network.

    :ivar deviceId: Id of the unit within the network.
    :ivar uuid: Globally unique id of the unit.
    :ivar address: MAC address of the unit.
    :ivar name: User assigned name of the unit.
    :ivar firmwareVersion: Firmware version of the unit.

    :ivar unitType: Type of the unit. Determines the capabilities.
    :ivar securityKey: Optional per-unit key (seen on some legacy/mixed networks). Not used yet.
    """

    _typeId: int
    deviceId: int
    uuid: str
    address: str
    name: str
    firmwareVersion: str

    unitType: UnitType
    securityKey: bytes | None = None
    networkProtocolVersion: int | None = None
    networkGrade: int | None = None

    _state: UnitState | None = None
    _on: bool = False
    _online: bool = False

    @property
    def state(self) -> UnitState | None:
        """Get the state of the unit if it has been set."""
        return self._state

    @property
    def is_on(self) -> bool:
        """Determine whether the unit is turned on."""
        if self.unitType.get_control(UnitControlType.ONOFF) and self._state:
            return self._on and self._state.onoff is True
        if self.unitType.get_control(UnitControlType.DIMMER) and self._state:
            return (
                self._on and self._state.dimmer is not None and self._state.dimmer > 0
            )
        else:
            return self._on

    @property
    def online(self) -> bool:
        return self._online

    def _prefer_raw_rgb(self) -> bool:
        """Return True if RGB control should be interpreted as raw RGB components.

        Some Classic networks (notably grade=0) appear to represent RGB controls as
        packed R/G/B components rather than Hue/Saturation.
        """
        env_mode = os.environ.get("CASAMBI_BT_RGB_ENCODING", "").strip().lower()
        if env_mode in ("raw", "rgb", "component", "components"):
            return True
        if env_mode in ("hs", "hsv", "huesat", "hue-sat"):
            return False

        return (
            self.networkProtocolVersion is not None
            and self.networkProtocolVersion < 10
            and self.networkGrade == 0
        )

    @staticmethod
    def _scale_u8_to_bits(value_u8: int, bits: int) -> int:
        """Scale an 8-bit value (0..255) to a `bits`-wide integer (0..(2**bits-1))."""
        if bits <= 0:
            return 0
        mask = (1 << bits) - 1
        if mask <= 0:
            return 0
        if mask == 0xFF:
            return value_u8 & 0xFF
        # Round to nearest representable value.
        return (value_u8 * mask + 127) // 255

    @staticmethod
    def _scale_bits_to_u8(value_bits: int, bits: int) -> int:
        """Scale a `bits`-wide integer (0..(2**bits-1)) to 8-bit (0..255)."""
        if bits <= 0:
            return 0
        mask = (1 << bits) - 1
        if mask <= 0:
            return 0
        value_bits &= mask
        if mask == 0xFF:
            return value_bits
        # Round to nearest u8.
        return (value_bits * 255 + (mask // 2)) // mask

    # TODO: Add tests for this method
    def getStateAsBytes(self, state: UnitState) -> bytes:
        """Given a generic UnitState convert it into the internal state representation.

        Unsupported state information will be ignored.
        """

        # offset, lenth, value
        values: list[tuple[int, int, int]] = []

        # TODO: Support for resolutions >8 byte?
        # Parse and convert state
        for c in self.unitType.controls:
            if c.type == UnitControlType.DIMMER and state.dimmer is not None:
                scaledValue = self._scale_u8_to_bits(state.dimmer, c.length)
            elif c.type == UnitControlType.VERTICAL and state.vertical is not None:
                scaledValue = self._scale_u8_to_bits(state.vertical, c.length)
            elif c.type == UnitControlType.RGB and state.rgb is not None:
                if (
                    self._prefer_raw_rgb()
                    and c.length % 3 == 0
                    and (c.length // 3) <= UnitState.RGB_RESOLUTION
                ):
                    compLen = c.length // 3
                    rgb_mask = 2**compLen - 1

                    r, g, b = state.rgb
                    r_bits = self._scale_u8_to_bits(r, compLen) & rgb_mask
                    g_bits = self._scale_u8_to_bits(g, compLen) & rgb_mask
                    b_bits = self._scale_u8_to_bits(b, compLen) & rgb_mask

                    # Match casambi-android (v3.16) packing for raw RGB controls:
                    # lowest bits = R, then G, highest = B.
                    scaledValue = (
                        (r_bits << (compLen * 0))
                        | (g_bits << (compLen * 1))
                        | (b_bits << (compLen * 2))
                    )
                else:
                    hueLen = (c.length * 10) // 18
                    hueMask = 2**hueLen - 1
                    satLen = c.length - hueLen
                    satMask = 2**satLen - 1

                    h, s = state.hs  # type: ignore[misc]

                    scaledValue = ((round(h * hueMask) & hueMask) << satLen) + (
                        round(s * satMask) & satMask
                    )
            elif c.type == UnitControlType.WHITE and state.white is not None:
                scaledValue = self._scale_u8_to_bits(state.white, c.length)
            elif (
                c.type == UnitControlType.TEMPERATURE
                and state.temperature is not None
                and c.min
                and c.max
            ):
                clampedTemp = min(c.max, max(c.min, state.temperature))
                tempMask = 2**c.length - 1
                scaledValue = (tempMask * (clampedTemp - c.min)) // (c.max - c.min)
            elif (
                c.type == UnitControlType.COLORSOURCE and state.colorsource is not None
            ):
                scaledValue = state.colorsource.value
            elif c.type == UnitControlType.XY and state.xy is not None:
                coordLen = c.length // 2
                x, y = state.xy
                xyMask = 2**coordLen - 1
                scaledValue = (round(x * xyMask) << coordLen) | round(y * xyMask)
            elif c.type == UnitControlType.SLIDER and state.slider is not None:
                scaledValue = self._scale_u8_to_bits(state.slider, c.length)
            elif c.type == UnitControlType.ONOFF and state.onoff is not None:
                scaledValue = 1 if state.onoff else 0

            # Use default if unsupported type or unset value in state
            else:
                scaledValue = c.default

            values.append((c.offset, c.length, scaledValue))

        # Pack state into bytes
        res = bytearray(self.unitType.stateLength)
        for off, len, val in values:
            val <<= off % 8
            byteLen = (len + off % 8 - 1) // 8 + 1
            valBytes = val.to_bytes(byteLen, byteorder="little", signed=False)
            for i in range(byteLen):
                res[off // 8] |= valBytes[i]
                off += 8 - off % 8

        _LOGGER.debug(f"Packing {values.__repr__()} as {res}")
        return bytes(res)

    # TODO: Add tests for this method
    def setStateFromBytes(self, value: bytes, *, byte_offset: int = 0) -> None:
        """Parse state bytes into a `UnitState` and set it for the current unit.

        Supports partial updates by merging the received bytes into a full-length
        state buffer before decoding controls.

        :param value: State bytes for the unit (may be partial).
        :param byte_offset: Byte offset where `value` applies within the full unit state.
        """
        full_state_len = self.unitType.stateLength
        if byte_offset < 0:
            byte_offset = 0
        if byte_offset > full_state_len:
            byte_offset = full_state_len

        if not self._state:
            self._state = UnitState()

        # Always decode from a full-length buffer.
        if (
            self._state._raw_state is not None
            and len(self._state._raw_state) == full_state_len
        ):
            merged = bytearray(self._state._raw_state)
        else:
            # Use a default-packed buffer rather than zero-fill to avoid manufacturing
            # impossible values for unset controls on the first partial update.
            merged = bytearray(self.getStateAsBytes(UnitState()))

        end_offset = min(byte_offset + len(value), full_state_len)
        if end_offset > byte_offset:
            merged[byte_offset:end_offset] = value[: end_offset - byte_offset]

        merged_bytes = bytes(merged)
        self._state._raw_state = merged_bytes
        self._state._unknown_controls = []

        # TODO: Support for resolutions >8 byte?
        for c in self.unitType.controls:
            # Extract all relevant bytes from the state
            byteLen = (c.length + c.offset % 8 - 1) // 8 + 1
            cBytes = merged_bytes[c.offset // 8 : c.offset // 8 + byteLen]

            # Extract c.Length bits form the byte string
            cInt = int.from_bytes(cBytes, byteorder="little", signed=False)
            cInt >>= c.offset % 8
            cInt &= 2**c.length - 1

            if c.type == UnitControlType.DIMMER:
                self._state.dimmer = self._scale_bits_to_u8(cInt, c.length)
            elif c.type == UnitControlType.VERTICAL:
                self._state.vertical = self._scale_bits_to_u8(cInt, c.length)
            elif c.type == UnitControlType.RGB:
                if (
                    self._prefer_raw_rgb()
                    and c.length % 3 == 0
                    and (c.length // 3) <= UnitState.RGB_RESOLUTION
                ):
                    compLen = c.length // 3
                    rgb_mask = 2**compLen - 1

                    # Match casambi-android (v3.16) unpacking for raw RGB controls:
                    # lowest bits = R, then G, highest = B.
                    r_bits = cInt & rgb_mask
                    g_bits = (cInt >> compLen) & rgb_mask
                    b_bits = (cInt >> (2 * compLen)) & rgb_mask

                    r = self._scale_bits_to_u8(r_bits, compLen)
                    g = self._scale_bits_to_u8(g_bits, compLen)
                    b = self._scale_bits_to_u8(b_bits, compLen)
                    self._state.rgb = (r, g, b)
                else:
                    hueLen = (c.length * 10) // 18
                    hueMask = 2**hueLen - 1
                    satLen = c.length - hueLen
                    satMask = 2**satLen - 1

                    h = (cInt >> satLen) / hueMask
                    s = (cInt & satMask) / satMask

                    self._state.hs = (h, s)
            elif c.type == UnitControlType.WHITE:
                self._state.white = self._scale_bits_to_u8(cInt, c.length)
            elif c.type == UnitControlType.TEMPERATURE:
                if not c.max or not c.min:
                    _LOGGER.warning("Can't set temperature when min or max unknown.")
                    continue
                tempRange = c.max - c.min
                tempMask = 2**c.length - 1
                # TODO: We should probalby try to make this number a bit more round
                self._state.temperature = int(((cInt / tempMask) * tempRange) + c.min)
            elif c.type == UnitControlType.COLORSOURCE:
                self._state.colorsource = ColorSource(cInt)
            elif c.type == UnitControlType.XY:
                coordLen = c.length // 2
                xyMask = 2**coordLen - 1
                y = cInt & xyMask
                x = (cInt >> coordLen) & xyMask
                self._state.xy = (x / xyMask, y / xyMask)
            elif c.type == UnitControlType.SLIDER:
                self._state.slider = self._scale_bits_to_u8(cInt, c.length)
            elif c.type == UnitControlType.ONOFF:
                self._state.onoff = cInt != 0
            elif c.type == UnitControlType.UNKOWN:
                # Might be useful for implementing more state types
                _LOGGER.debug(
                    f"Value for unkown control type at {c.offset}: {cInt}. Unit type is {self.unitType.id}."
                )
                self._state._unknown_controls.append((c.offset, c.length, cInt))

        _LOGGER.debug(f"Parsed {b2a(merged_bytes)} to {self.state.__repr__()}")


@dataclass
class Scene:
    """A scene in a network.

    :ivar sceneId: The id of the scene in the network.
    :ivar name: The name of the scene.
    """

    sceneId: int
    name: str


@dataclass
class Group:
    """A group (collection of units) in a network.

    :ivar groupId: The id of the group in the network.
    :ivar name: The name of the group.
    :ivar units: A list of units in this group.
    """

    groudId: int
    name: str

    units: list[Unit]
