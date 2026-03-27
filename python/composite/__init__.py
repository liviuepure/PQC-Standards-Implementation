"""Composite Signature Schemes — ML-DSA + Ed25519 / ECDSA-P256."""

from composite.composite_sig import (
    CompositeScheme,
    MLDSA65_ED25519,
    MLDSA65_ECDSA_P256,
    MLDSA87_ED25519,
    MLDSA44_ED25519,
    key_gen,
    sign,
    verify,
)

__all__ = [
    "CompositeScheme",
    "MLDSA65_ED25519",
    "MLDSA65_ECDSA_P256",
    "MLDSA87_ED25519",
    "MLDSA44_ED25519",
    "key_gen",
    "sign",
    "verify",
]
