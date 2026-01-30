from enum import IntEnum, unique
from typing import Final

DEVICE_NAME: Final = "Casambi BT Python"

CASA_UUID: Final = "0000fe4d-0000-1000-8000-00805f9b34fb"
CASA_AUTH_CHAR_UUID: Final = "c9ffde48-ca5a-0001-ab83-8f519b482f77"

# Classic firmware/protocol uses different GATT characteristics (see casambi-android t1.C1713d):
# - 0000ca51-...: connection hash (first 8 bytes are used as CMAC input prefix)
# - 0000ca52-...: signed data channel (write + notify)
CASA_UUID_CLASSIC: Final = "0000ca5a-0000-1000-8000-00805f9b34fb"
CASA_CLASSIC_HASH_CHAR_UUID: Final = "0000ca51-0000-1000-8000-00805f9b34fb"
CASA_CLASSIC_DATA_CHAR_UUID: Final = "0000ca52-0000-1000-8000-00805f9b34fb"


@unique
class ConnectionState(IntEnum):
    NONE = 0
    CONNECTED = 1
    KEY_EXCHANGED = 2
    AUTHENTICATED = 3
    ERROR = 99
