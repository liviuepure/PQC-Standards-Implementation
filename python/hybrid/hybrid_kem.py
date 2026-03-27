"""Hybrid KEM: combining classical ECDH with ML-KEM.

Hybrid KEMs ensure security holds if either the classical or
post-quantum component remains secure.

Supported schemes:
- X25519 + ML-KEM-768 (IETF standard hybrid for TLS)
- ECDH-P256 + ML-KEM-768
- X25519 + ML-KEM-1024
- ECDH-P384 + ML-KEM-1024

KDF: SHA3-256(ss_classical || ss_pq || label)
"""

import hashlib
from dataclasses import dataclass
from typing import Optional

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mlkem.kem import keygen as mlkem_keygen, encaps as mlkem_encaps, decaps as mlkem_decaps
from mlkem.params import ML_KEM_768, ML_KEM_1024, MLKEMParams
from hybrid.x25519 import x25519_keygen, x25519_encaps, x25519_decaps


def _sha3_256(*inputs: bytes) -> bytes:
    """SHA3-256 of concatenated inputs."""
    h = hashlib.sha3_256()
    for inp in inputs:
        h.update(inp)
    return h.digest()


def _combine_secrets(ss_classical: bytes, ss_pq: bytes, label: bytes) -> bytes:
    """Combine shared secrets: SHA3-256(ss_classical || ss_pq || label)."""
    return _sha3_256(ss_classical, ss_pq, label)


@dataclass(frozen=True)
class HybridScheme:
    """Definition of a hybrid KEM scheme."""
    name: str
    label: bytes
    classical_type: str  # "x25519", "P-256", or "P-384"
    mlkem_params: MLKEMParams


@dataclass
class HybridKeyPair:
    """Hybrid key pair."""
    ek: bytes
    dk: bytes
    classical_ek_size: int
    classical_dk_size: int


@dataclass
class HybridEncapsResult:
    """Result of hybrid encapsulation."""
    shared_secret: bytes
    ciphertext: bytes
    classical_ct_size: int


# Scheme definitions
X25519_MLKEM768 = HybridScheme(
    name="X25519-MLKEM768",
    label=b"X25519-MLKEM768",
    classical_type="x25519",
    mlkem_params=ML_KEM_768,
)

ECDHP256_MLKEM768 = HybridScheme(
    name="ECDHP256-MLKEM768",
    label=b"ECDHP256-MLKEM768",
    classical_type="P-256",
    mlkem_params=ML_KEM_768,
)

X25519_MLKEM1024 = HybridScheme(
    name="X25519-MLKEM1024",
    label=b"X25519-MLKEM1024",
    classical_type="x25519",
    mlkem_params=ML_KEM_1024,
)

ECDHP384_MLKEM1024 = HybridScheme(
    name="ECDHP384-MLKEM1024",
    label=b"ECDHP384-MLKEM1024",
    classical_type="P-384",
    mlkem_params=ML_KEM_1024,
)


def _classical_keygen(classical_type: str) -> tuple[bytes, bytes]:
    """Generate a classical key pair."""
    if classical_type == "x25519":
        return x25519_keygen()
    else:
        from hybrid.ecdh_nist import ecdh_keygen
        pk, sk, _ = ecdh_keygen(classical_type)
        return pk, sk


def _classical_encaps(classical_type: str, peer_pk: bytes) -> tuple[bytes, bytes]:
    """Classical KEM-style encapsulation."""
    if classical_type == "x25519":
        return x25519_encaps(peer_pk)
    else:
        from hybrid.ecdh_nist import ecdh_encaps
        return ecdh_encaps(classical_type, peer_pk)


def _classical_decaps(classical_type: str, sk: bytes, ct: bytes) -> bytes:
    """Classical KEM-style decapsulation."""
    if classical_type == "x25519":
        return x25519_decaps(sk, ct)
    else:
        from hybrid.ecdh_nist import ecdh_decaps
        return ecdh_decaps(classical_type, sk, ct)


def hybrid_keygen(scheme: HybridScheme) -> HybridKeyPair:
    """Generate a hybrid key pair.

    Args:
        scheme: The hybrid KEM scheme to use.

    Returns:
        HybridKeyPair with combined keys.
    """
    classical_pk, classical_sk = _classical_keygen(scheme.classical_type)
    pq_ek, pq_dk = mlkem_keygen(scheme.mlkem_params)

    ek = classical_pk + pq_ek
    dk = classical_sk + pq_dk

    return HybridKeyPair(
        ek=ek,
        dk=dk,
        classical_ek_size=len(classical_pk),
        classical_dk_size=len(classical_sk),
    )


def hybrid_encaps(scheme: HybridScheme, ek: bytes, classical_ek_size: int) -> HybridEncapsResult:
    """Hybrid encapsulation.

    Args:
        scheme: The hybrid KEM scheme.
        ek: Combined encapsulation key.
        classical_ek_size: Size of the classical portion.

    Returns:
        HybridEncapsResult with shared secret and ciphertext.
    """
    classical_pk = ek[:classical_ek_size]
    pq_ek = ek[classical_ek_size:]

    ss_classical, ct_classical = _classical_encaps(scheme.classical_type, classical_pk)
    ss_pq, ct_pq = mlkem_encaps(pq_ek, scheme.mlkem_params)

    combined_ss = _combine_secrets(ss_classical, ss_pq, scheme.label)

    return HybridEncapsResult(
        shared_secret=combined_ss,
        ciphertext=ct_classical + ct_pq,
        classical_ct_size=len(ct_classical),
    )


def hybrid_decaps(
    scheme: HybridScheme,
    dk: bytes,
    ct: bytes,
    classical_dk_size: int,
    classical_ct_size: int,
) -> bytes:
    """Hybrid decapsulation.

    Args:
        scheme: The hybrid KEM scheme.
        dk: Combined decapsulation key.
        ct: Combined ciphertext.
        classical_dk_size: Size of the classical secret key portion.
        classical_ct_size: Size of the classical ciphertext portion.

    Returns:
        32-byte combined shared secret.
    """
    classical_sk = dk[:classical_dk_size]
    pq_dk = dk[classical_dk_size:]

    ct_classical = ct[:classical_ct_size]
    ct_pq = ct[classical_ct_size:]

    ss_classical = _classical_decaps(scheme.classical_type, classical_sk, ct_classical)
    ss_pq = mlkem_decaps(pq_dk, ct_pq, scheme.mlkem_params)

    return _combine_secrets(ss_classical, ss_pq, scheme.label)
