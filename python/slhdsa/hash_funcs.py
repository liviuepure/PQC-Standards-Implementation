"""Hash function families for SLH-DSA per FIPS 205, Sections 11.1 and 11.2."""

import hashlib
import hmac as _hmac

from slhdsa.address import ADRS


# ---------------------------------------------------------------------------
# SHAKE-based suite (Section 11.1)
# ---------------------------------------------------------------------------

def _shake256(data: bytes, out_len: int) -> bytes:
    h = hashlib.shake_256(data)
    return h.digest(out_len)


class ShakeSuite:
    """SHAKE-256 based hash function suite."""

    @staticmethod
    def H_msg(r: bytes, pk_seed: bytes, pk_root: bytes, m: bytes, out_len: int) -> bytes:
        """Hash message (Algorithm 22 / SHAKE variant)."""
        return _shake256(r + pk_seed + pk_root + m, out_len)

    @staticmethod
    def PRF(pk_seed: bytes, sk_seed: bytes, adrs: ADRS, n: int) -> bytes:
        """PRF for secret key generation."""
        return _shake256(pk_seed + adrs.to_bytes() + sk_seed, n)

    @staticmethod
    def PRF_msg(sk_prf: bytes, opt_rand: bytes, m: bytes, n: int) -> bytes:
        """PRF for randomized signing."""
        return _shake256(sk_prf + opt_rand + m, n)

    @staticmethod
    def F(pk_seed: bytes, adrs: ADRS, m1: bytes, n: int) -> bytes:
        """Tweakable hash F (single n-byte block)."""
        return _shake256(pk_seed + adrs.to_bytes() + m1, n)

    @staticmethod
    def H(pk_seed: bytes, adrs: ADRS, m1m2: bytes, n: int) -> bytes:
        """Tweakable hash H (two n-byte blocks)."""
        return _shake256(pk_seed + adrs.to_bytes() + m1m2, n)

    @staticmethod
    def T(pk_seed: bytes, adrs: ADRS, m: bytes, n: int) -> bytes:
        """Tweakable hash T_l (variable length)."""
        return _shake256(pk_seed + adrs.to_bytes() + m, n)


# ---------------------------------------------------------------------------
# SHA2-based suite (Section 11.2)
# ---------------------------------------------------------------------------

def _mgf1_sha256(seed: bytes, length: int) -> bytes:
    """MGF1 with SHA-256 (RFC 8017)."""
    result = b""
    counter = 0
    while len(result) < length:
        c = counter.to_bytes(4, "big")
        result += hashlib.sha256(seed + c).digest()
        counter += 1
    return result[:length]


def _mgf1_sha512(seed: bytes, length: int) -> bytes:
    """MGF1 with SHA-512."""
    result = b""
    counter = 0
    while len(result) < length:
        c = counter.to_bytes(4, "big")
        result += hashlib.sha512(seed + c).digest()
        counter += 1
    return result[:length]


class SHA2Suite:
    """SHA-256/SHA-512 based hash function suite.

    For n=16 (128-bit security): uses SHA-256.
    For n=24,32 (192/256-bit security): uses SHA-512 for most, SHA-256 for F/PRF.
    """

    @staticmethod
    def _sha256(data: bytes, out_len: int) -> bytes:
        return hashlib.sha256(data).digest()[:out_len]

    @staticmethod
    def _sha512(data: bytes, out_len: int) -> bytes:
        return hashlib.sha512(data).digest()[:out_len]

    @staticmethod
    def H_msg(r: bytes, pk_seed: bytes, pk_root: bytes, m: bytes, out_len: int) -> bytes:
        n = len(pk_seed)
        if n == 16:
            mgf_seed = r + pk_seed + SHA2Suite._sha256(r + pk_seed + pk_root + m, 32)
            return _mgf1_sha256(mgf_seed, out_len)
        else:
            mgf_seed = r + pk_seed + SHA2Suite._sha512(r + pk_seed + pk_root + m, 64)
            return _mgf1_sha512(mgf_seed, out_len)

    @staticmethod
    def PRF(pk_seed: bytes, sk_seed: bytes, adrs: ADRS, n: int) -> bytes:
        # Compress ADRS to 22 bytes for SHA2 (Section 11.2.1)
        compressed = _compress_adrs(adrs)
        if n == 16:
            return hashlib.sha256(pk_seed + compressed + sk_seed).digest()[:n]
        else:
            return hashlib.sha256(pk_seed + compressed + sk_seed).digest()[:n]

    @staticmethod
    def PRF_msg(sk_prf: bytes, opt_rand: bytes, m: bytes, n: int) -> bytes:
        if n == 16:
            return _hmac_sha256(sk_prf, opt_rand + m)[:n]
        else:
            return _hmac_sha512(sk_prf, opt_rand + m)[:n]

    @staticmethod
    def F(pk_seed: bytes, adrs: ADRS, m1: bytes, n: int) -> bytes:
        compressed = _compress_adrs(adrs)
        if n == 16:
            return hashlib.sha256(pk_seed + compressed + m1).digest()[:n]
        else:
            return hashlib.sha256(pk_seed + compressed + m1).digest()[:n]

    @staticmethod
    def H(pk_seed: bytes, adrs: ADRS, m1m2: bytes, n: int) -> bytes:
        compressed = _compress_adrs(adrs)
        if n == 16:
            return hashlib.sha256(pk_seed + compressed + m1m2).digest()[:n]
        else:
            return hashlib.sha512(pk_seed + compressed + m1m2).digest()[:n]

    @staticmethod
    def T(pk_seed: bytes, adrs: ADRS, m: bytes, n: int) -> bytes:
        compressed = _compress_adrs(adrs)
        if n == 16:
            inblock = pk_seed + compressed + m
            return hashlib.sha256(inblock).digest()[:n]
        else:
            inblock = pk_seed + compressed + m
            return hashlib.sha512(inblock).digest()[:n]


def _compress_adrs(adrs: ADRS) -> bytes:
    """Compress 32-byte ADRS to 22 bytes for SHA2 suite (Section 11.2.1).

    Drops the first 3 bytes of layer (keep byte 3),
    drops the first 4 bytes of tree address (keep bytes 8..15),
    keeps type word (4 bytes) but only last byte,
    keeps 3 type-specific words (12 bytes).
    Total: 1 + 8 + 1 + 12 = 22 bytes.
    """
    raw = adrs.to_bytes()
    return (
        raw[3:4]      # layer: 1 byte
        + raw[8:16]   # tree address: 8 bytes
        + raw[19:20]  # type: 1 byte
        + raw[20:32]  # 3 type-specific words: 12 bytes
    )


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha256).digest()


def _hmac_sha512(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha512).digest()


def get_suite(hash_type: str):
    """Return the appropriate hash suite for the given type."""
    if hash_type == "shake":
        return ShakeSuite
    elif hash_type == "sha2":
        return SHA2Suite
    else:
        raise ValueError(f"Unknown hash type: {hash_type}")
