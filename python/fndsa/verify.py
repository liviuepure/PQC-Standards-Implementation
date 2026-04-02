"""FN-DSA verification (FIPS 206 Algorithm 4)."""

from .params import Params, Q
from .encode import decode_pk, decode_sig
from .ntt import poly_mul_ntt
from .sign import hash_to_point


def _center_mod_q(v: int) -> int:
    """Reduce v mod Q and center in (-Q/2, Q/2]."""
    v = ((v % Q) + Q) % Q
    if v > Q // 2:
        v -= Q
    return v


def _norm_sq(s1: list[int], s2: list[int]) -> int:
    """Compute squared Euclidean norm of (s1, s2)."""
    return sum(v * v for v in s1) + sum(v * v for v in s2)


def verify(pk: bytes, msg: bytes, sig: bytes, params: Params) -> bool:
    """Verify an FN-DSA signature (FIPS 206 Algorithm 4).

    Returns True iff sig is a valid FN-DSA signature on msg under public key pk
    for parameter set params.
    """
    # 1. Decode and validate public key
    h = decode_pk(pk, params)
    if h is None:
        return False

    # 2. Decode and validate signature
    result = decode_sig(sig, params)
    if result is None:
        return False
    salt, s1 = result

    # 3. Recompute c = HashToPoint(salt || msg)
    hash_input = salt + msg
    c = hash_to_point(hash_input, params)

    # 4. Compute s2 = c - s1*h (mod q), centered in (-Q/2, Q/2]
    n = params.n
    s1_mod_q = [((v % Q) + Q) % Q for v in s1]
    s1h = poly_mul_ntt(s1_mod_q, h, n)
    s2 = [_center_mod_q(c[i] - s1h[i]) for i in range(n)]

    # 5. Norm check: ||(s1, s2)||^2 <= beta^2
    return _norm_sq(s1, s2) <= params.beta_sq
