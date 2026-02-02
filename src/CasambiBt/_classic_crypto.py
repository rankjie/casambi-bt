"""Classic Casambi protocol helpers (CMAC signing/verification).

Ground truth:
- casambi-android `t1.P.o(...)` calculates a CMAC over:
    connection_hash[0:8] + payload
  and stores the CMAC (prefix) into the packet header.

The CMAC input structure from t1.P.o():
    kVar.i(rVar.f16699L, 0, 8);  // connection_hash[0:8]
    kVar.i(b(), this.f16551t + i9, (c() - i9) - this.f16551t);  // payload starting at seq offset

For "conformant" classic (rVar.Z=true):
    CMAC input = conn_hash[0:8] || seq(2 bytes BE) || command_bytes

For "legacy" classic (rVar.Z=false):
    CMAC input = conn_hash[0:8] || command_bytes

Test vectors based on community BLE captures (GitHub lkempf/casambi-bt#17):

Capture from sMauldaeschle:
    Raw packet: 0215db43c40004040200b3
    - Byte 0: 02 (auth level = visitor)
    - Bytes 1-4: 15db43c4 (4-byte CMAC signature)
    - Byte 5: 00 (padding/marker)
    - Byte 6: 04 (counter/sequence)
    - Byte 7: 04 (unit id)
    - Byte 8: 02 (length of parameters)
    - Byte 9: 00 (dimmer value)
    - Byte 10: b3 (temperature/vertical value)

Capture from FliegenKLATSCH:
    Raw packet: 0200 43A2 9600 0203 0254 FF
    - Bytes 0-1: 0200 (auth 02, then...)
    - Bytes 2-5: 43A2 9600 (first 4 bytes of CMAC)
    - The CMAC input was: <8 bytes connection hash> 00 0203 0254 FF
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers.algorithms import AES

if TYPE_CHECKING:
    pass

_logger = logging.getLogger(__name__)


def classic_cmac(key: bytes, conn_hash8: bytes, payload: bytes, *, debug: bool = False) -> bytes:
    """Compute the Classic CMAC (16 bytes) over connection hash + payload.

    Args:
        key: 16-byte AES key (visitor or manager key from cloud)
        conn_hash8: First 8 bytes of the connection hash read from CA51/auth char
        payload: The data to sign (for conformant: seq + command; for legacy: command only)
        debug: If True, log CMAC input/output for debugging

    Returns:
        16-byte CMAC
    """
    if len(conn_hash8) != 8:
        raise ValueError("conn_hash8 must be 8 bytes")

    cmac_input = conn_hash8 + payload
    cmac = CMAC(AES(key))
    cmac.update(cmac_input)
    result = cmac.finalize()

    if debug:
        _logger.warning(
            "[CLASSIC_CMAC_DEBUG] key_len=%d conn_hash8=%s payload_len=%d payload_prefix=%s cmac=%s",
            len(key),
            conn_hash8.hex(),
            len(payload),
            payload[:16].hex() if len(payload) > 16 else payload.hex(),
            result.hex(),
        )

    return result


def classic_cmac_prefix(
    key: bytes, conn_hash8: bytes, payload: bytes, prefix_len: int, *, debug: bool = False
) -> bytes:
    """Return the prefix bytes that are embedded into the Classic packet header.

    Args:
        key: 16-byte AES key
        conn_hash8: First 8 bytes of connection hash
        payload: Data to sign
        prefix_len: Number of CMAC bytes to use (4 for visitor, 16 for manager)
        debug: If True, log CMAC computation

    Returns:
        First prefix_len bytes of the CMAC
    """
    mac = classic_cmac(key, conn_hash8, payload, debug=debug)
    return mac[:prefix_len]


def verify_classic_cmac(
    key: bytes, conn_hash8: bytes, payload: bytes, expected_prefix: bytes
) -> bool:
    """Verify a Classic CMAC signature prefix.

    Args:
        key: 16-byte AES key
        conn_hash8: First 8 bytes of connection hash
        payload: Data that was signed
        expected_prefix: The CMAC prefix from the packet header

    Returns:
        True if the computed CMAC prefix matches expected_prefix
    """
    computed = classic_cmac_prefix(key, conn_hash8, payload, len(expected_prefix))
    return computed == expected_prefix


# Test vectors from RFC 4493 (AES-CMAC) - used in test_classic_protocol.py
# These confirm our CMAC implementation is correct.
RFC4493_TEST_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
RFC4493_VECTORS = [
    # (message, expected_cmac)
    (bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
     bytes.fromhex("070a16b46b4d4144f79bdd9dd04a287c")),
    (bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"),
     bytes.fromhex("ce0cbf1738f4df6428b1d93bf12081c9")),
]

# Placeholder for real Casambi test vectors once we have them from captures
# Format: (visitor_key, conn_hash8, payload_after_header, expected_cmac_prefix_4, description)
CASAMBI_CLASSIC_TEST_VECTORS: list[tuple[bytes, bytes, bytes, bytes, str]] = [
    # These will be populated from real BLE captures
    # Example structure (not verified yet):
    # (
    #     bytes.fromhex("...16 byte key..."),
    #     bytes.fromhex("...8 byte conn hash..."),
    #     bytes.fromhex("...payload after auth byte..."),
    #     bytes.fromhex("...4 byte expected cmac..."),
    #     "Description of what this packet does"
    # ),
]

