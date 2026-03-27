"""Pure Python Ed25519 implementation (RFC 8032).

This is a reference implementation for the composite signature scheme.
It implements Ed25519 sign and verify using only the Python standard library.
"""

import hashlib
import os

# ---------------------------------------------------------------------------
# Curve25519 / Ed25519 constants
# ---------------------------------------------------------------------------

# Field prime: p = 2^255 - 19
P = 2**255 - 19

# Group order
L = 2**252 + 27742317777372353535851937790883648493

# d coefficient: -121665/121666 mod p
D = -121665 * pow(121666, P - 2, P) % P

# I = sqrt(-1) mod p
I = pow(2, (P - 1) // 4, P)


def _recover_x(y: int, sign_bit: int) -> int:
    """Recover x from y and the sign bit."""
    y2 = y * y % P
    x2 = (y2 - 1) * pow(D * y2 + 1, P - 2, P) % P
    if x2 == 0:
        if sign_bit:
            raise ValueError("Invalid point")
        return 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * I % P
    if (x * x - x2) % P != 0:
        raise ValueError("Not a valid y coordinate")
    if x % 2 != sign_bit:
        x = P - x
    return x


# Base point
BY = 4 * pow(5, P - 2, P) % P
BX = _recover_x(BY, 0)
B = (BX, BY, 1, BX * BY % P)  # Extended coordinates (X, Y, Z, T)


# ---------------------------------------------------------------------------
# Extended coordinate point arithmetic
# ---------------------------------------------------------------------------

def _point_add(p1, p2):
    """Add two points in extended coordinates (X, Y, Z, T)."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    dd = 2 * z1 * z2 % P
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    x3 = e * f % P
    y3 = g * h % P
    z3 = f * g % P
    t3 = e * h % P
    return (x3, y3, z3, t3)


def _point_double(p1):
    """Double a point in extended coordinates (a=-1 twisted Edwards)."""
    # Just use point_add(p1, p1) for correctness.
    return _point_add(p1, p1)


def _scalar_mult(scalar: int, point):
    """Scalar multiplication using double-and-add."""
    result = (0, 1, 1, 0)  # Identity point
    current = point
    s = scalar
    while s > 0:
        if s & 1:
            result = _point_add(result, current)
        current = _point_double(current)
        s >>= 1
    return result


def _encode_point(point) -> bytes:
    """Encode an extended-coordinate point to 32 bytes."""
    x, y, z, _ = point
    zi = pow(z, P - 2, P)
    xo = x * zi % P
    yo = y * zi % P
    encoded = bytearray(yo.to_bytes(32, 'little'))
    # Set high bit of last byte if x is odd
    encoded[31] |= (xo & 1) << 7
    return bytes(encoded)


def _decode_point(data: bytes):
    """Decode a 32-byte point to extended coordinates."""
    if len(data) != 32:
        raise ValueError("Point must be 32 bytes")
    ba = bytearray(data)
    sign_bit = (ba[31] >> 7) & 1
    ba[31] &= 0x7F
    y = int.from_bytes(ba, 'little')
    if y >= P:
        raise ValueError("y out of range")
    x = _recover_x(y, sign_bit)
    return (x, y, 1, x * y % P)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _clamp(secret: bytes) -> int:
    """Clamp the private scalar per RFC 8032."""
    h = _sha512(secret)
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return int.from_bytes(a, 'little')


def _sc_reduce(data: bytes) -> int:
    """Reduce a 64-byte hash to a scalar mod L."""
    return int.from_bytes(data, 'little') % L


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def keygen(seed: bytes | None = None) -> tuple[bytes, bytes]:
    """Generate Ed25519 key pair.

    Args:
        seed: 32-byte secret seed. Random if None.

    Returns:
        (public_key, secret_seed) each 32 bytes.
    """
    if seed is None:
        seed = os.urandom(32)
    if len(seed) != 32:
        raise ValueError("Seed must be 32 bytes")

    a = _clamp(seed)
    A = _scalar_mult(a, B)
    pk = _encode_point(A)
    return pk, seed


def sign(secret: bytes, msg: bytes) -> bytes:
    """Sign a message with Ed25519.

    Args:
        secret: 32-byte secret seed.
        msg: Arbitrary-length message.

    Returns:
        64-byte signature.
    """
    h = _sha512(secret)
    a = _clamp(secret)
    prefix = h[32:]

    A = _scalar_mult(a, B)
    pk = _encode_point(A)

    # r = SHA-512(prefix || msg) mod L
    r_hash = _sha512(prefix + msg)
    r = _sc_reduce(r_hash)

    # R = r * B
    R = _scalar_mult(r, B)
    R_enc = _encode_point(R)

    # S = (r + SHA-512(R || A || msg) * a) mod L
    k_hash = _sha512(R_enc + pk + msg)
    k = _sc_reduce(k_hash)
    S = (r + k * a) % L

    return R_enc + S.to_bytes(32, 'little')


def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify an Ed25519 signature.

    Args:
        pk: 32-byte public key.
        msg: Original message.
        sig: 64-byte signature.

    Returns:
        True if valid.
    """
    if len(sig) != 64 or len(pk) != 32:
        return False

    try:
        A = _decode_point(pk)
    except (ValueError, ZeroDivisionError):
        return False

    R_enc = sig[:32]
    try:
        R = _decode_point(R_enc)
    except (ValueError, ZeroDivisionError):
        return False

    S = int.from_bytes(sig[32:], 'little')
    if S >= L:
        return False

    # Check: 8*S*B == 8*R + 8*SHA-512(R||A||msg)*A
    k_hash = _sha512(R_enc + pk + msg)
    k = _sc_reduce(k_hash)

    # S*B
    SB = _scalar_mult(S, B)
    # k*A
    kA = _scalar_mult(k, A)
    # R + k*A
    RkA = _point_add(R, kA)

    # Compare by encoding (clears cofactor via 8x multiply)
    lhs = _scalar_mult(8, SB)
    rhs = _scalar_mult(8, RkA)

    return _encode_point(lhs) == _encode_point(rhs)
