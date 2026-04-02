"""HQC parameter sets (NIST HQC standard)."""

from dataclasses import dataclass


@dataclass(frozen=True)
class HQCParams:
    """Parameters for an HQC instance."""
    name: str
    n: int          # Length of the code (ring dimension for x^n - 1)
    n1: int         # RS code length
    n2: int         # RM code length (must be power of 2, here 128 * multiplicity)
    k: int          # RS message length (bytes)
    delta: int      # RS error correction capability (n1 - 2*delta = k for systematic RS)
    w: int          # Hamming weight for secret key vectors
    wr: int         # Hamming weight for encaps randomness r1
    we: int         # Hamming weight for encaps randomness e
    pk_size: int    # Public key size in bytes
    sk_size: int    # Secret key size in bytes
    ct_size: int    # Ciphertext size in bytes
    security: int   # Security level in bits
    multiplicity: int  # RM repetition multiplicity

    @property
    def n1n2(self) -> int:
        """Total tensor code length = n1 * n2."""
        return self.n1 * self.n2


# GF(256) irreducible polynomial: x^8 + x^4 + x^3 + x^2 + 1 = 0x11D
GF256_POLY = 0x11D
GF256_GEN = 2  # primitive element alpha = x


HQC_128 = HQCParams(
    name="HQC-128",
    n=17669,
    n1=46,
    n2=384,       # 128 * 3
    k=16,
    delta=15,
    w=66,
    wr=77,
    we=77,
    pk_size=2249,
    sk_size=2289,
    ct_size=4481,
    security=128,
    multiplicity=3,
)

HQC_192 = HQCParams(
    name="HQC-192",
    n=35851,
    n1=56,
    n2=640,       # 128 * 5
    k=24,
    delta=16,
    w=100,
    wr=117,
    we=117,
    pk_size=4522,
    sk_size=4562,
    ct_size=9026,
    security=192,
    multiplicity=5,
)

HQC_256 = HQCParams(
    name="HQC-256",
    n=57637,
    n1=90,
    n2=640,       # 128 * 5
    k=32,
    delta=29,
    w=131,
    wr=153,
    we=153,
    pk_size=7245,
    sk_size=7285,
    ct_size=14469,
    security=256,
    multiplicity=5,
)
