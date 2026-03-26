"""SLH-DSA parameter sets per FIPS 205."""

from dataclasses import dataclass


@dataclass(frozen=True)
class SLHDSAParams:
    name: str
    n: int           # Security parameter (hash output length in bytes)
    h: int           # Total tree height
    d: int           # Number of hypertree layers
    hp: int          # Height of each tree (h // d)
    a: int           # FORS tree height
    k: int           # Number of FORS trees
    lg_w: int        # Winternitz parameter log2(w)
    w: int           # Winternitz parameter
    m: int           # Message digest length in bytes
    hash_type: str   # "shake" or "sha2"
    robust: bool     # True for robust, False for simple (FIPS 205 uses simple)

    @property
    def wots_len1(self) -> int:
        """WOTS+ len1 = ceil(8n / lg_w)."""
        return (8 * self.n + self.lg_w - 1) // self.lg_w

    @property
    def wots_len2(self) -> int:
        """WOTS+ len2 = floor(log2(len1 * (w-1)) / lg_w) + 1."""
        import math
        val = self.wots_len1 * (self.w - 1)
        return math.floor(math.log2(val) / self.lg_w) + 1

    @property
    def wots_len(self) -> int:
        """Total WOTS+ chain count."""
        return self.wots_len1 + self.wots_len2

    @property
    def wots_sig_bytes(self) -> int:
        return self.wots_len * self.n

    @property
    def pk_size(self) -> int:
        """Public key: PK.seed || PK.root, each n bytes."""
        return 2 * self.n

    @property
    def sk_size(self) -> int:
        """Secret key: SK.seed || SK.prf || PK.seed || PK.root."""
        return 4 * self.n

    @property
    def sig_size(self) -> int:
        """Signature size in bytes per FIPS 205."""
        # R (n bytes) + FORS sig (k*(a+1)*n) + HT sig (d * (wots_len + hp) * n)
        fors_sig = self.k * (self.a + 1) * self.n
        ht_sig = self.d * (self.wots_len + self.hp) * self.n
        return self.n + fors_sig + ht_sig


def _make_params(name, n, h, d, a, k, lg_w, m, hash_type):
    return SLHDSAParams(
        name=name, n=n, h=h, d=d, hp=h // d, a=a, k=k,
        lg_w=lg_w, w=2**lg_w, m=m, hash_type=hash_type, robust=False,
    )


# SHAKE-based parameter sets (FIPS 205, Table 1)
SLH_DSA_SHAKE_128s = _make_params("SLH-DSA-SHAKE-128s", 16, 63, 7, 12, 14, 4, 30, "shake")
SLH_DSA_SHAKE_128f = _make_params("SLH-DSA-SHAKE-128f", 16, 66, 22, 6, 33, 4, 34, "shake")
SLH_DSA_SHAKE_192s = _make_params("SLH-DSA-SHAKE-192s", 24, 63, 7, 14, 17, 4, 39, "shake")
SLH_DSA_SHAKE_192f = _make_params("SLH-DSA-SHAKE-192f", 24, 66, 22, 8, 33, 4, 42, "shake")
SLH_DSA_SHAKE_256s = _make_params("SLH-DSA-SHAKE-256s", 32, 64, 8, 14, 22, 4, 47, "shake")
SLH_DSA_SHAKE_256f = _make_params("SLH-DSA-SHAKE-256f", 32, 68, 17, 9, 35, 4, 49, "shake")

# SHA2-based parameter sets (FIPS 205, Table 1)
SLH_DSA_SHA2_128s = _make_params("SLH-DSA-SHA2-128s", 16, 63, 7, 12, 14, 4, 30, "sha2")
SLH_DSA_SHA2_128f = _make_params("SLH-DSA-SHA2-128f", 16, 66, 22, 6, 33, 4, 34, "sha2")
SLH_DSA_SHA2_192s = _make_params("SLH-DSA-SHA2-192s", 24, 63, 7, 14, 17, 4, 39, "sha2")
SLH_DSA_SHA2_192f = _make_params("SLH-DSA-SHA2-192f", 24, 66, 22, 8, 33, 4, 42, "sha2")
SLH_DSA_SHA2_256s = _make_params("SLH-DSA-SHA2-256s", 32, 64, 8, 14, 22, 4, 47, "sha2")
SLH_DSA_SHA2_256f = _make_params("SLH-DSA-SHA2-256f", 32, 68, 17, 9, 35, 4, 49, "sha2")

ALL_PARAMS = [
    SLH_DSA_SHAKE_128s, SLH_DSA_SHAKE_128f,
    SLH_DSA_SHAKE_192s, SLH_DSA_SHAKE_192f,
    SLH_DSA_SHAKE_256s, SLH_DSA_SHAKE_256f,
    SLH_DSA_SHA2_128s, SLH_DSA_SHA2_128f,
    SLH_DSA_SHA2_192s, SLH_DSA_SHA2_192f,
    SLH_DSA_SHA2_256s, SLH_DSA_SHA2_256f,
]
