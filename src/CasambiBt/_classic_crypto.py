"""Classic Casambi protocol helpers (CMAC signing/verification).

Ground truth:
- casambi-android `t1.P.o(...)` calculates a CMAC over:
    connection_hash[0:8] + payload
  and stores the CMAC (prefix) into the packet header.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers.algorithms import AES


def classic_cmac(key: bytes, conn_hash8: bytes, payload: bytes) -> bytes:
    """Compute the Classic CMAC (16 bytes) over connection hash + payload."""
    if len(conn_hash8) != 8:
        raise ValueError("conn_hash8 must be 8 bytes")
    cmac = CMAC(AES(key))
    cmac.update(conn_hash8)
    cmac.update(payload)
    return cmac.finalize()


def classic_cmac_prefix(
    key: bytes, conn_hash8: bytes, payload: bytes, prefix_len: int
) -> bytes:
    """Return the prefix bytes that are embedded into the Classic packet header."""
    mac = classic_cmac(key, conn_hash8, payload)
    return mac[:prefix_len]

