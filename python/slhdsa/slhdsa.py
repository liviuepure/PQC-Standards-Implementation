"""SLH-DSA top-level keygen, sign, verify per FIPS 205, Section 9."""

import os
import math

from slhdsa.params import SLHDSAParams
from slhdsa.address import ADRS, FORS_TREE
from slhdsa.hash_funcs import get_suite
from slhdsa.hypertree import ht_sign, ht_verify
from slhdsa.fors import fors_sign, fors_pk_from_sig
from slhdsa.xmss import xmss_node
from slhdsa.utils import to_int


def keygen(params: SLHDSAParams) -> tuple:
    """SLH-DSA key generation (Algorithm 17).

    Returns:
        (pk, sk) where pk = PK.seed || PK.root and
        sk = SK.seed || SK.prf || PK.seed || PK.root.
    """
    sk_seed = os.urandom(params.n)
    sk_prf = os.urandom(params.n)
    pk_seed = os.urandom(params.n)

    adrs = ADRS()
    adrs.set_layer_address(params.d - 1)
    adrs.set_tree_address(0)

    pk_root = xmss_node(params, sk_seed, 0, params.hp, pk_seed, adrs)

    pk = pk_seed + pk_root
    sk = sk_seed + sk_prf + pk_seed + pk_root
    return pk, sk


def sign(sk: bytes, m: bytes, params: SLHDSAParams,
         randomize: bool = True) -> bytes:
    """SLH-DSA signature generation (Algorithm 18).

    Args:
        sk: Secret key.
        m: Message to sign.
        params: Parameter set.
        randomize: If True, use randomized signing.

    Returns:
        SLH-DSA signature.
    """
    suite = get_suite(params.hash_type)
    n = params.n

    # Parse secret key
    sk_seed = sk[0:n]
    sk_prf = sk[n:2*n]
    pk_seed = sk[2*n:3*n]
    pk_root = sk[3*n:4*n]

    # Generate randomizer
    if randomize:
        opt_rand = os.urandom(n)
    else:
        opt_rand = pk_seed

    # R = PRF_msg(SK.prf, opt_rand, M)
    r = suite.PRF_msg(sk_prf, opt_rand, m, n)

    # Generate message digest
    sig = r  # First part of signature

    digest = suite.H_msg(r, pk_seed, pk_root, m, params.m)

    # Split digest into md, idx_tree, idx_leaf
    # md: ceil(k*a / 8) bytes
    # idx_tree: ceil((h - h/d) / 8) bytes
    # idx_leaf: ceil((h/d) / 8) bytes
    md_len = math.ceil(params.k * params.a / 8)
    tree_bits = params.h - params.hp
    tree_len = math.ceil(tree_bits / 8)
    leaf_len = math.ceil(params.hp / 8)

    md = digest[0:md_len]
    idx_tree_bytes = digest[md_len:md_len + tree_len]
    idx_leaf_bytes = digest[md_len + tree_len:md_len + tree_len + leaf_len]

    idx_tree = to_int(idx_tree_bytes) % (1 << tree_bits)
    idx_leaf = to_int(idx_leaf_bytes) % (1 << params.hp)

    # FORS signature
    adrs = ADRS()
    adrs.set_layer_address(0)
    adrs.set_tree_address(idx_tree)
    adrs.set_type(FORS_TREE)
    adrs.set_key_pair_address(idx_leaf)

    sig_fors = fors_sign(params, md, sk_seed, pk_seed, adrs)
    sig += sig_fors

    # Get FORS public key for HT signing
    pk_fors = fors_pk_from_sig(params, sig_fors, md, pk_seed, adrs)

    # Hypertree signature
    sig_ht = ht_sign(params, pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf)
    sig += sig_ht

    return sig


def verify(pk: bytes, m: bytes, sig: bytes, params: SLHDSAParams) -> bool:
    """SLH-DSA signature verification (Algorithm 19).

    Args:
        pk: Public key.
        m: Message.
        sig: Signature.
        params: Parameter set.

    Returns:
        True if signature is valid.
    """
    suite = get_suite(params.hash_type)
    n = params.n

    if len(sig) != params.sig_size:
        return False
    if len(pk) != params.pk_size:
        return False

    # Parse public key
    pk_seed = pk[0:n]
    pk_root = pk[n:2*n]

    # Parse signature
    r = sig[0:n]
    fors_sig_size = params.k * (params.a + 1) * n
    sig_fors = sig[n:n + fors_sig_size]
    sig_ht = sig[n + fors_sig_size:]

    # Recompute message digest
    digest = suite.H_msg(r, pk_seed, pk_root, m, params.m)

    md_len = math.ceil(params.k * params.a / 8)
    tree_bits = params.h - params.hp
    tree_len = math.ceil(tree_bits / 8)
    leaf_len = math.ceil(params.hp / 8)

    md = digest[0:md_len]
    idx_tree_bytes = digest[md_len:md_len + tree_len]
    idx_leaf_bytes = digest[md_len + tree_len:md_len + tree_len + leaf_len]

    idx_tree = to_int(idx_tree_bytes) % (1 << tree_bits)
    idx_leaf = to_int(idx_leaf_bytes) % (1 << params.hp)

    # Recompute FORS public key
    adrs = ADRS()
    adrs.set_layer_address(0)
    adrs.set_tree_address(idx_tree)
    adrs.set_type(FORS_TREE)
    adrs.set_key_pair_address(idx_leaf)

    pk_fors = fors_pk_from_sig(params, sig_fors, md, pk_seed, adrs)

    # Verify hypertree signature
    return ht_verify(params, pk_fors, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root)
