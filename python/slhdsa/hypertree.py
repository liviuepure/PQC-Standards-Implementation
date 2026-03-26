"""Hypertree signature for SLH-DSA per FIPS 205, Section 8."""

from slhdsa.params import SLHDSAParams
from slhdsa.address import ADRS
from slhdsa.xmss import xmss_sign, xmss_pk_from_sig, xmss_node


def ht_sign(params: SLHDSAParams, m: bytes, sk_seed: bytes,
            pk_seed: bytes, idx_tree: int, idx_leaf: int) -> bytes:
    """Hypertree signature generation (Algorithm 11 / HT).

    Args:
        m: n-byte message to sign.
        idx_tree: Tree index.
        idx_leaf: Leaf index within the tree.

    Returns:
        Hypertree signature (d XMSS signatures concatenated).
    """
    adrs = ADRS()
    adrs.set_layer_address(0)
    adrs.set_tree_address(idx_tree)

    sig_tmp = xmss_sign(params, m, sk_seed, idx_leaf, pk_seed, adrs)
    sig_ht = sig_tmp

    root = xmss_pk_from_sig(params, idx_leaf, sig_tmp, m, pk_seed, adrs)

    for j in range(1, params.d):
        idx_leaf = idx_tree % (1 << params.hp)
        idx_tree = idx_tree >> params.hp
        adrs.set_layer_address(j)
        adrs.set_tree_address(idx_tree)
        sig_tmp = xmss_sign(params, root, sk_seed, idx_leaf, pk_seed, adrs)
        sig_ht += sig_tmp

        if j < params.d - 1:
            root = xmss_pk_from_sig(params, idx_leaf, sig_tmp, root, pk_seed, adrs)

    return sig_ht


def ht_verify(params: SLHDSAParams, m: bytes, sig_ht: bytes,
              pk_seed: bytes, idx_tree: int, idx_leaf: int,
              pk_root: bytes) -> bool:
    """Hypertree signature verification (Algorithm 12 / HT).

    Returns:
        True if the signature is valid.
    """
    adrs = ADRS()
    xmss_sig_size = (params.wots_len + params.hp) * params.n

    adrs.set_layer_address(0)
    adrs.set_tree_address(idx_tree)

    sig_tmp = sig_ht[:xmss_sig_size]
    node = xmss_pk_from_sig(params, idx_leaf, sig_tmp, m, pk_seed, adrs)

    for j in range(1, params.d):
        idx_leaf = idx_tree % (1 << params.hp)
        idx_tree = idx_tree >> params.hp
        adrs.set_layer_address(j)
        adrs.set_tree_address(idx_tree)
        sig_tmp = sig_ht[j * xmss_sig_size:(j + 1) * xmss_sig_size]
        node = xmss_pk_from_sig(params, idx_leaf, sig_tmp, node, pk_seed, adrs)

    return node == pk_root
