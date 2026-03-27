"""Hash functions and XOF/PRF per FIPS 203.

Uses Python's hashlib which provides SHA3 and SHAKE in Python 3.10+.
"""
from __future__ import annotations

import hashlib


def G(data: bytes) -> tuple[bytes, bytes]:
    """G: SHA3-512, split output at 32 bytes into (rho, sigma)."""
    h = hashlib.sha3_512(data).digest()
    return h[:32], h[32:]


def H(data: bytes) -> bytes:
    """H: SHA3-256, returns 32 bytes."""
    return hashlib.sha3_256(data).digest()


def J(data: bytes) -> bytes:
    """J: SHAKE-256, returns 32 bytes."""
    return hashlib.shake_256(data).digest(32)


def xof(rho: bytes, i: int, j: int) -> bytes:
    """XOF: SHAKE-128(rho || j || i), returns 672 bytes.

    Note: FIPS 203 specifies the order as (rho || j || i).
    """
    input_bytes = rho + bytes([j, i])
    return hashlib.shake_128(input_bytes).digest(672)


def prf(s: bytes, b: int, length: int) -> bytes:
    """PRF: SHAKE-256(s || b), returns 'length' bytes."""
    input_bytes = s + bytes([b])
    return hashlib.shake_256(input_bytes).digest(length)
