"""FN-DSA (FIPS 206 / FALCON) parameter sets."""

from dataclasses import dataclass

Q = 12289


@dataclass(frozen=True)
class Params:
    name: str
    n: int
    log_n: int
    padded: bool
    pk_size: int
    sk_size: int
    sig_size: int    # max for non-padded; exact for padded
    beta_sq: int
    fg_bits: int     # 6 for n=512, 5 for n=1024


FNDSA512 = Params("FN-DSA-512", 512, 9, False, 897, 1281, 666, 34034726, 6)
FNDSA1024 = Params("FN-DSA-1024", 1024, 10, False, 1793, 2305, 1280, 70265242, 5)
FNDSAPadded512 = Params("FN-DSA-PADDED-512", 512, 9, True, 897, 1281, 809, 34034726, 6)
FNDSAPadded1024 = Params("FN-DSA-PADDED-1024", 1024, 10, True, 1793, 2305, 1473, 70265242, 5)
