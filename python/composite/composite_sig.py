"""Composite Signature Schemes — ML-DSA + Ed25519.

Signature format: len(sig_classical) [4 bytes LE] || sig_classical || sig_pq

Security holds as long as either the classical or PQ component is secure.
"""

import struct
from dataclasses import dataclass

from composite.ed25519_pure import (
    keygen as ed25519_keygen,
    sign as ed25519_sign,
    verify as ed25519_verify,
)
from mldsa.dsa import keygen as mldsa_keygen, sign as mldsa_sign, verify as mldsa_verify
from mldsa.params import ML_DSA_44, ML_DSA_65, ML_DSA_87, MLDSAParams


@dataclass(frozen=True)
class CompositeScheme:
    name: str
    pq_params: MLDSAParams
    classical: str  # "ed25519" or "ecdsa-p256"

    @property
    def classical_pk_size(self) -> int:
        return 32 if self.classical == "ed25519" else 65

    @property
    def classical_sk_size(self) -> int:
        return 32  # seed for Ed25519 or scalar for ECDSA


MLDSA65_ED25519 = CompositeScheme(
    name="ML-DSA-65+Ed25519",
    pq_params=ML_DSA_65,
    classical="ed25519",
)

MLDSA65_ECDSA_P256 = CompositeScheme(
    name="ML-DSA-65+ECDSA-P256",
    pq_params=ML_DSA_65,
    classical="ecdsa-p256",
)

MLDSA87_ED25519 = CompositeScheme(
    name="ML-DSA-87+Ed25519",
    pq_params=ML_DSA_87,
    classical="ed25519",
)

MLDSA44_ED25519 = CompositeScheme(
    name="ML-DSA-44+Ed25519",
    pq_params=ML_DSA_44,
    classical="ed25519",
)


@dataclass
class CompositeKeyPair:
    pk: bytes   # pk_classical || pk_pq
    sk: bytes   # sk_classical || sk_pq
    scheme: CompositeScheme


def key_gen(scheme: CompositeScheme) -> CompositeKeyPair:
    """Generate a composite key pair."""
    if scheme.classical == "ed25519":
        classical_pk, classical_sk = ed25519_keygen()
    else:
        raise NotImplementedError(
            "ECDSA-P256 not implemented in pure Python; use Ed25519 schemes"
        )

    pq_pk, pq_sk = mldsa_keygen(scheme.pq_params)

    pk = classical_pk + pq_pk
    sk = classical_sk + pq_sk
    return CompositeKeyPair(pk=pk, sk=sk, scheme=scheme)


def sign(kp: CompositeKeyPair, msg: bytes) -> bytes:
    """Produce a composite signature on msg.

    Returns: len(sig_classical)[4 LE] || sig_classical || sig_pq
    """
    sk_classical = kp.sk[: kp.scheme.classical_sk_size]
    sk_pq = kp.sk[kp.scheme.classical_sk_size :]

    if kp.scheme.classical == "ed25519":
        sig_classical = ed25519_sign(sk_classical, msg)
    else:
        raise NotImplementedError("ECDSA-P256 not in pure Python")

    sig_pq = mldsa_sign(sk_pq, msg, kp.scheme.pq_params)

    return struct.pack("<I", len(sig_classical)) + sig_classical + sig_pq


def verify(scheme: CompositeScheme, pk: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify a composite signature. Returns True only if BOTH components verify."""
    if len(sig) < 4:
        return False

    classical_sig_len = struct.unpack("<I", sig[:4])[0]
    if len(sig) < 4 + classical_sig_len:
        return False

    sig_classical = sig[4 : 4 + classical_sig_len]
    sig_pq = sig[4 + classical_sig_len :]

    pk_classical = pk[: scheme.classical_pk_size]
    pk_pq = pk[scheme.classical_pk_size :]

    if scheme.classical == "ed25519":
        classical_ok = ed25519_verify(pk_classical, msg, sig_classical)
    else:
        return False  # ECDSA-P256 not in pure Python

    pq_ok = mldsa_verify(pk_pq, msg, sig_pq, scheme.pq_params)

    return classical_ok and pq_ok
