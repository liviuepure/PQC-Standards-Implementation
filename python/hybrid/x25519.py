"""Pure Python X25519 (Curve25519 Diffie-Hellman) implementation.

Implements RFC 7748 X25519 function using the Montgomery ladder.
This is a minimal, zero-dependency implementation for use in the
hybrid KEM combiner.
"""

import os

# Field prime: p = 2^255 - 19
P = (1 << 255) - 19

# a24 = 121666 (from the curve equation)
A24 = 121666


def _clamp(k: bytes) -> int:
    """Clamp a 32-byte scalar per RFC 7748."""
    scalar = bytearray(k)
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return int.from_bytes(scalar, "little")


def _mod_inv(x: int, p: int = P) -> int:
    """Modular inverse using Fermat's little theorem: x^(p-2) mod p."""
    return pow(x, p - 2, p)


def x25519(k: bytes, u: bytes) -> bytes:
    """X25519 function per RFC 7748.

    Args:
        k: 32-byte scalar (private key).
        u: 32-byte u-coordinate (public key or base point).

    Returns:
        32-byte shared secret (u-coordinate of result).
    """
    scalar = _clamp(k)
    u_int = int.from_bytes(u, "little") % P

    # Montgomery ladder
    x_1 = u_int
    x_2 = 1
    z_2 = 0
    x_3 = u_int
    z_3 = 1
    swap = 0

    for t in range(254, -1, -1):
        k_t = (scalar >> t) & 1
        swap ^= k_t
        # Conditional swap
        x_2, x_3 = (x_3, x_2) if swap else (x_2, x_3)
        z_2, z_3 = (z_3, z_2) if swap else (z_2, z_3)
        swap = k_t

        A = (x_2 + z_2) % P
        AA = (A * A) % P
        B = (x_2 - z_2) % P
        BB = (B * B) % P
        E = (AA - BB) % P
        C = (x_3 + z_3) % P
        D = (x_3 - z_3) % P
        DA = (D * A) % P
        CB = (C * B) % P
        x_3 = pow(DA + CB, 2, P)
        z_3 = (x_1 * pow(DA - CB, 2, P)) % P
        x_2 = (AA * BB) % P
        z_2 = (E * (AA + A24 * E)) % P

    # Final conditional swap
    x_2, x_3 = (x_3, x_2) if swap else (x_2, x_3)
    z_2, z_3 = (z_3, z_2) if swap else (z_2, z_3)

    result = (x_2 * _mod_inv(z_2)) % P
    return result.to_bytes(32, "little")


# The base point for Curve25519 (u = 9)
BASEPOINT = (9).to_bytes(32, "little")


def x25519_keygen() -> tuple[bytes, bytes]:
    """Generate an X25519 key pair.

    Returns:
        (public_key, private_key) each 32 bytes.
    """
    sk = os.urandom(32)
    pk = x25519(sk, BASEPOINT)
    return pk, sk


def x25519_encaps(peer_pk: bytes) -> tuple[bytes, bytes]:
    """X25519 KEM-style encapsulation.

    Generate an ephemeral key pair and compute shared secret with peer.

    Args:
        peer_pk: 32-byte peer public key.

    Returns:
        (shared_secret, ephemeral_public_key) each 32 bytes.
    """
    eph_pk, eph_sk = x25519_keygen()
    ss = x25519(eph_sk, peer_pk)
    return ss, eph_pk


def x25519_decaps(sk: bytes, ct: bytes) -> bytes:
    """X25519 KEM-style decapsulation.

    Compute shared secret from our secret key and peer's ephemeral public key.

    Args:
        sk: 32-byte secret key.
        ct: 32-byte ephemeral public key (ciphertext).

    Returns:
        32-byte shared secret.
    """
    return x25519(sk, ct)
