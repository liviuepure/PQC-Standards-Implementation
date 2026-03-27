"""NIST curve ECDH (P-256, P-384) for hybrid KEM.

Uses the `cryptography` package for NIST curve operations.
X25519 is implemented from scratch in x25519.py and does not require this.

If only X25519+ML-KEM is needed, this module is not required.
"""

import os

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        NoEncryption,
    )
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False


def _require_cryptography():
    if not _HAS_CRYPTOGRAPHY:
        raise ImportError(
            "NIST curve ECDH requires the 'cryptography' package. "
            "Install with: pip install cryptography. "
            "X25519+ML-KEM works without any external dependencies."
        )


def ecdh_keygen(curve_name: str) -> tuple[bytes, bytes, object]:
    """Generate an ECDH key pair on a NIST curve.

    Args:
        curve_name: "P-256" or "P-384".

    Returns:
        (public_key_bytes, private_key_bytes, private_key_object).
    """
    _require_cryptography()
    curve = ec.SECP256R1() if curve_name == "P-256" else ec.SECP384R1()
    sk = ec.generate_private_key(curve)
    pk = sk.public_key()
    pk_bytes = pk.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    sk_numbers = sk.private_numbers()
    sk_len = 32 if curve_name == "P-256" else 48
    sk_bytes = sk_numbers.private_value.to_bytes(sk_len, "big")
    return pk_bytes, sk_bytes, sk


def ecdh_encaps(curve_name: str, peer_pk_bytes: bytes) -> tuple[bytes, bytes]:
    """ECDH KEM-style encapsulation on a NIST curve.

    Args:
        curve_name: "P-256" or "P-384".
        peer_pk_bytes: Peer's public key (uncompressed point).

    Returns:
        (shared_secret, ephemeral_public_key_bytes).
    """
    _require_cryptography()
    curve = ec.SECP256R1() if curve_name == "P-256" else ec.SECP384R1()
    peer_pk = ec.EllipticCurvePublicKey.from_encoded_point(curve, peer_pk_bytes)

    eph_sk = ec.generate_private_key(curve)
    eph_pk = eph_sk.public_key()
    eph_pk_bytes = eph_pk.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    shared_key = eph_sk.exchange(ec.ECDH(), peer_pk)
    return shared_key, eph_pk_bytes


def ecdh_decaps(curve_name: str, sk_bytes: bytes, ct_bytes: bytes) -> bytes:
    """ECDH KEM-style decapsulation on a NIST curve.

    Args:
        curve_name: "P-256" or "P-384".
        sk_bytes: Our secret key bytes.
        ct_bytes: Ephemeral public key from encapsulation.

    Returns:
        Shared secret bytes.
    """
    _require_cryptography()
    curve = ec.SECP256R1() if curve_name == "P-256" else ec.SECP384R1()
    peer_pk = ec.EllipticCurvePublicKey.from_encoded_point(curve, ct_bytes)

    sk_int = int.from_bytes(sk_bytes, "big")
    # Reconstruct the private key from the scalar
    # We need the public key too — derive it from the scalar
    pub_numbers = ec.derive_private_key(sk_int, curve).public_key().public_numbers()
    sk = ec.derive_private_key(sk_int, curve)

    shared_key = sk.exchange(ec.ECDH(), peer_pk)
    return shared_key
