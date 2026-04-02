"""GF(256) = GF(2^8) arithmetic with irreducible polynomial 0x11D.

The irreducible polynomial is x^8 + x^4 + x^3 + x^2 + 1.
The primitive element alpha = x (i.e., 2 in integer representation).
"""

from hqc.params import GF256_POLY

# Precompute log and exp tables
_EXP_TABLE = [0] * 256  # alpha^i for i in [0, 254], with _EXP_TABLE[255] = 0
_LOG_TABLE = [0] * 256  # discrete log base alpha, _LOG_TABLE[0] is undefined


def _init_tables():
    """Build GF(256) exponential and logarithm tables."""
    x = 1
    for i in range(255):
        _EXP_TABLE[i] = x
        _LOG_TABLE[x] = i
        x <<= 1  # multiply by alpha = x
        if x & 0x100:
            x ^= GF256_POLY  # reduce modulo the irreducible polynomial
    _EXP_TABLE[255] = 0  # sentinel
    _LOG_TABLE[0] = 0  # undefined, but set to 0 for safety


_init_tables()


def gf256_exp(i: int) -> int:
    """Return alpha^i in GF(256)."""
    return _EXP_TABLE[i % 255]


def gf256_log(a: int) -> int:
    """Return discrete log base alpha of a in GF(256). a must be nonzero."""
    if a == 0:
        raise ValueError("log(0) is undefined in GF(256)")
    return _LOG_TABLE[a]


def gf256_mul(a: int, b: int) -> int:
    """Multiply two elements in GF(256)."""
    if a == 0 or b == 0:
        return 0
    return _EXP_TABLE[(_LOG_TABLE[a] + _LOG_TABLE[b]) % 255]


def gf256_inv(a: int) -> int:
    """Multiplicative inverse of a in GF(256). a must be nonzero."""
    if a == 0:
        raise ValueError("inverse of 0 is undefined in GF(256)")
    return _EXP_TABLE[(255 - _LOG_TABLE[a]) % 255]


def gf256_pow(a: int, n: int) -> int:
    """Compute a^n in GF(256)."""
    if a == 0:
        return 0 if n > 0 else 1
    return _EXP_TABLE[(_LOG_TABLE[a] * n) % 255]


def gf256_add(a: int, b: int) -> int:
    """Add two elements in GF(256) (XOR)."""
    return a ^ b


def gf256_div(a: int, b: int) -> int:
    """Divide a by b in GF(256)."""
    if b == 0:
        raise ValueError("division by zero in GF(256)")
    if a == 0:
        return 0
    return _EXP_TABLE[(_LOG_TABLE[a] - _LOG_TABLE[b]) % 255]
