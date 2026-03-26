"""WOTS+ one-time signature for SLH-DSA per FIPS 205, Section 5."""

from slhdsa.params import SLHDSAParams
from slhdsa.address import ADRS, WOTS_HASH, WOTS_PK, WOTS_PRF
from slhdsa.hash_funcs import get_suite
from slhdsa.utils import base_2b, to_byte


def chain(params: SLHDSAParams, x: bytes, i: int, s: int,
          pk_seed: bytes, adrs: ADRS) -> bytes:
    """Chaining function (Algorithm 4).

    Applies F iteratively s times starting from step i.
    """
    if s == 0:
        return x
    if (i + s) > (params.w - 1):
        return None

    suite = get_suite(params.hash_type)
    tmp = chain(params, x, i, s - 1, pk_seed, adrs)
    adrs.set_hash_address(i + s - 1)
    tmp = suite.F(pk_seed, adrs, tmp, params.n)
    return tmp


def chain_iterative(params: SLHDSAParams, x: bytes, i: int, s: int,
                    pk_seed: bytes, adrs: ADRS) -> bytes:
    """Iterative version of chain to avoid deep recursion."""
    if s == 0:
        return x
    if (i + s) > (params.w - 1):
        return None

    suite = get_suite(params.hash_type)
    tmp = x
    for j in range(i, i + s):
        adrs.set_hash_address(j)
        tmp = suite.F(pk_seed, adrs, tmp, params.n)
    return tmp


def wots_pkgen(params: SLHDSAParams, sk_seed: bytes, pk_seed: bytes,
               adrs: ADRS) -> bytes:
    """WOTS+ public key generation (Algorithm 5)."""
    suite = get_suite(params.hash_type)
    wots_pk_adrs = adrs.copy()

    tmp = b""
    for i in range(params.wots_len):
        # Generate secret key element
        sk_adrs = adrs.copy()
        sk_adrs.set_type(WOTS_PRF)
        sk_adrs.set_key_pair_address(adrs.get_key_pair_address())
        sk_adrs.set_chain_address(i)
        sk_adrs.set_hash_address(0)
        sk = suite.PRF(pk_seed, sk_seed, sk_adrs, params.n)

        # Chain to get public key element
        wots_chain_adrs = adrs.copy()
        wots_chain_adrs.set_type(WOTS_HASH)
        wots_chain_adrs.set_key_pair_address(adrs.get_key_pair_address())
        wots_chain_adrs.set_chain_address(i)
        tmp += chain_iterative(params, sk, 0, params.w - 1, pk_seed, wots_chain_adrs)

    # Compress public key
    wots_pk_adrs.set_type(WOTS_PK)
    wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    pk = suite.T(pk_seed, wots_pk_adrs, tmp, params.n)
    return pk


def wots_sign(params: SLHDSAParams, m: bytes, sk_seed: bytes,
              pk_seed: bytes, adrs: ADRS) -> bytes:
    """WOTS+ signature generation (Algorithm 6).

    Args:
        m: n-byte message digest to sign.
    """
    suite = get_suite(params.hash_type)

    # Convert message to base-w representation
    msg = base_2b(m, params.lg_w, params.wots_len1)

    # Compute checksum
    csum = 0
    for v in msg:
        csum += params.w - 1 - v

    # Pad checksum to full bytes and convert to base-w
    csum_bits = params.wots_len2 * params.lg_w
    csum_bytes = (csum_bits + 7) // 8
    csum_b = to_byte(csum << (8 * csum_bytes - csum_bits), csum_bytes)
    msg_csum = msg + base_2b(csum_b, params.lg_w, params.wots_len2)

    sig = b""
    for i in range(params.wots_len):
        sk_adrs = adrs.copy()
        sk_adrs.set_type(WOTS_PRF)
        sk_adrs.set_key_pair_address(adrs.get_key_pair_address())
        sk_adrs.set_chain_address(i)
        sk_adrs.set_hash_address(0)
        sk = suite.PRF(pk_seed, sk_seed, sk_adrs, params.n)

        chain_adrs = adrs.copy()
        chain_adrs.set_type(WOTS_HASH)
        chain_adrs.set_key_pair_address(adrs.get_key_pair_address())
        chain_adrs.set_chain_address(i)
        sig += chain_iterative(params, sk, 0, msg_csum[i], pk_seed, chain_adrs)

    return sig


def wots_pk_from_sig(params: SLHDSAParams, sig: bytes, m: bytes,
                     pk_seed: bytes, adrs: ADRS) -> bytes:
    """Compute WOTS+ public key from signature (Algorithm 7)."""
    suite = get_suite(params.hash_type)

    # Convert message to base-w
    msg = base_2b(m, params.lg_w, params.wots_len1)

    csum = 0
    for v in msg:
        csum += params.w - 1 - v

    csum_bits = params.wots_len2 * params.lg_w
    csum_bytes = (csum_bits + 7) // 8
    csum_b = to_byte(csum << (8 * csum_bytes - csum_bits), csum_bytes)
    msg_csum = msg + base_2b(csum_b, params.lg_w, params.wots_len2)

    tmp = b""
    for i in range(params.wots_len):
        chain_adrs = adrs.copy()
        chain_adrs.set_type(WOTS_HASH)
        chain_adrs.set_key_pair_address(adrs.get_key_pair_address())
        chain_adrs.set_chain_address(i)
        sig_i = sig[i * params.n:(i + 1) * params.n]
        tmp += chain_iterative(params, sig_i, msg_csum[i],
                               params.w - 1 - msg_csum[i], pk_seed, chain_adrs)

    wots_pk_adrs = adrs.copy()
    wots_pk_adrs.set_type(WOTS_PK)
    wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    pk = suite.T(pk_seed, wots_pk_adrs, tmp, params.n)
    return pk
