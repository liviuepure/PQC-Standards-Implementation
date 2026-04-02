"""RCDT Gaussian sampler for FN-DSA (FIPS 206).

Uses the 18-entry 72-bit RCDT table from the FALCON spec (matching Go reference).
Python's arbitrary-precision integers give exact 72-bit comparisons without
any precision issues.

sigma0 = 1.8205 is the base Gaussian standard deviation.
"""
import math
import struct

# sigma0: base Gaussian parameter for the RCDT sampler (FIPS 206 §3.12).
SIGMA0 = 1.8205

# RCDT table: 18 entries, each a 72-bit threshold stored as (hi: int, lo: int).
# Full 72-bit value = (hi << 64) | lo.
# table[i] = floor(2^72 * Pr[|Z| >= i+1]) where Z ~ D_{Z, sigma0}.
# Values taken directly from Go reference (gaussian.go).
_RCDT_TABLE = [
    (199, 16610441552002023424),
    (103, 7624082642567692288),
    (42,  919243735747002368),
    (13,  3484267233246674944),
    (3,   2772878652510347264),
    (0,   10479598105528201216),
    (0,   1418221736465465344),
    (0,   143439473028577328),
    (0,   10810581864167812),
    (0,   605874652027744),
    (0,   25212870589170),
    (0,   778215157694),
    (0,   17802250993),
    (0,   301647562),
    (0,   3784361),
    (0,   35141),
    (0,   241),
    (0,   1),
]

# Precompute 72-bit integer representations for exact comparison
_RCDT_72 = [(hi << 64) | lo for hi, lo in _RCDT_TABLE]


def _sample_base_gaussian(rng) -> int:
    """Sample from D_{Z, sigma0} using the RCDT table.

    Reads 9 bytes (72 bits) of randomness for the table comparison,
    then 1 byte for the sign. Returns a signed integer in [-18, 18].

    All 18 table comparisons always execute (constant-time property).
    """
    # Read 9 bytes (72 bits) from CSPRNG.
    buf = rng(9)
    # Interpret as little-endian 72-bit integer.
    # lo = bytes 0..7 (little-endian uint64), hi = byte 8 (uint8).
    lo = int.from_bytes(buf[:8], 'little')
    hi = buf[8]
    sample = (hi << 64) | lo

    # Count how many RCDT entries are strictly greater than sample.
    z = 0
    for threshold in _RCDT_72:
        # Constant-time: always evaluate all entries.
        if sample < threshold:
            z += 1

    # Read 1 byte for the sign; use the lowest bit.
    sign_buf = rng(1)
    sign_bit = sign_buf[0] & 1
    # Apply sign: if sign_bit=1, negate z; otherwise keep z.
    # Branchless: result = z XOR mask - mask  (mask = 0 or -1)
    mask = -sign_bit  # 0 if sign_bit=0, -1 (all ones) if sign_bit=1
    result = (z ^ mask) - mask  # z if sign=0, -z if sign=1
    return result


def sample_gaussian(sigma: float, rng=None) -> int:
    """Sample from discrete Gaussian D_{Z, sigma} using RCDT rejection sampling.

    Parameters:
        sigma: target standard deviation (must be >= sigma0 = 1.8205)
        rng: callable(n_bytes) -> bytes, defaults to os.urandom

    Implements FIPS 206 §3.12 Algorithm 13 scalar variant.
    For sigma == sigma0 the rejection step always accepts.
    """
    import os
    if rng is None:
        rng = os.urandom

    sigma2 = sigma * sigma
    sigma02 = SIGMA0 * SIGMA0

    # c = (sigma^2 - sigma0^2) / (2 * sigma^2 * sigma0^2)
    # When sigma == sigma0: c = 0, exp(-z^2 * c) = 1 -> always accept.
    c = (sigma2 - sigma02) / (2.0 * sigma2 * sigma02)

    while True:
        z = _sample_base_gaussian(rng)

        # Rejection step: accept with probability exp(-z^2 * c).
        fz = float(z)
        log_prob = -fz * fz * c  # <= 0

        # Sample u in [0, 1) using 53 random bits (float64 mantissa precision).
        u_buf = rng(8)
        u53 = int.from_bytes(u_buf, 'little') >> 11  # 53-bit integer
        u = u53 / (1 << 53)  # in [0, 1)

        if u < math.exp(log_prob):
            return z
