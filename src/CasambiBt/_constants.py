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
CASA_CLASSIC_CA53_CHAR_UUID: Final = "0000ca53-0000-1000-8000-00805f9b34fb"

# Classic "conformant" firmware maps the legacy CA5A/CA5x UUIDs onto the FE4D service.
# Ground truth: casambi-android `t1.C1713d.e(UUID)` mapping:
# - CA52 -> 0001 (same as CASA_AUTH_CHAR_UUID)
# - CA51 -> 0002
# - CA53 -> 0003
CASA_CLASSIC_CONFORMANT_CA51_CHAR_UUID: Final = "c9ffde48-ca5a-0002-ab83-8f519b482f77"
CASA_CLASSIC_CONFORMANT_CA53_CHAR_UUID: Final = "c9ffde48-ca5a-0003-ab83-8f519b482f77"


@unique
class ConnectionState(IntEnum):
    NONE = 0
    CONNECTED = 1
    KEY_EXCHANGED = 2
    AUTHENTICATED = 3
    ERROR = 99
