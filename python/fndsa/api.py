"""FN-DSA public API — thin wrappers over the internal modules."""
import os

from .params import Params
from .ntru import ntru_keygen
from .encode import encode_pk, encode_sk
from .ntt import poly_mul_ntt, poly_inv_ntt
from .sign import sign_internal
from .verify import verify as _verify


def keygen(params: Params, rng=None) -> tuple[bytes, bytes]:
    """Generate an FN-DSA key pair.

    Returns (pk, sk) as bytes.
    rng: optional callable(n_bytes) -> bytes, defaults to os.urandom.
    """
    if rng is None:
        rng = os.urandom

    f, g, F = ntru_keygen(params, rng)

    # Compute h = g * f^{-1} mod q via NTT
    n = params.n
    from .params import Q as _Q
    f_mod_q = [((v % _Q) + _Q) % _Q for v in f]
    g_mod_q = [((v % _Q) + _Q) % _Q for v in g]

    h = poly_inv_ntt(f_mod_q, n)
    h = poly_mul_ntt(g_mod_q, h, n)

    pk = encode_pk(h, params)
    sk = encode_sk(f, g, F, params)
    return pk, sk


def sign(sk: bytes, msg: bytes, params: Params, rng=None) -> bytes:
    """Sign a message with a secret key.

    Returns signature bytes.
    rng: optional callable(n_bytes) -> bytes, defaults to os.urandom.
    """
    if rng is None:
        rng = os.urandom
    return sign_internal(sk, msg, params, rng)


def verify(pk: bytes, msg: bytes, sig: bytes, params: Params) -> bool:
    """Verify an FN-DSA signature.

    Returns True if the signature is valid, False otherwise.
    """
    return _verify(pk, msg, sig, params)
