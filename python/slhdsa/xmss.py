"""XMSS functions for SLH-DSA per FIPS 205, Section 6."""

from slhdsa.params import SLHDSAParams
from slhdsa.address import ADRS, TREE, WOTS_HASH
from slhdsa.hash_funcs import get_suite
from slhdsa.wots import wots_pkgen, wots_sign, wots_pk_from_sig


def xmss_node(params: SLHDSAParams, sk_seed: bytes, i: int, z: int,
              pk_seed: bytes, adrs: ADRS) -> bytes:
    """Compute internal XMSS node (Algorithm 8).

    Args:
        i: Node index at height z.
        z: Target height in the XMSS tree.
    """
    suite = get_suite(params.hash_type)

    if z > params.hp or i >= (1 << (params.hp - z)):
        return None

    if z == 0:
        # Leaf node: WOTS+ public key
        adrs.set_type(WOTS_HASH)
        adrs.set_key_pair_address(i)
        return wots_pkgen(params, sk_seed, pk_seed, adrs)
    else:
        # Internal node
        lnode = xmss_node(params, sk_seed, 2 * i, z - 1, pk_seed, adrs)
        rnode = xmss_node(params, sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)

        adrs.set_type(TREE)
        adrs.set_tree_height(z)
        adrs.set_tree_index(i)
        return suite.H(pk_seed, adrs, lnode + rnode, params.n)


def xmss_sign(params: SLHDSAParams, m: bytes, sk_seed: bytes, idx: int,
              pk_seed: bytes, adrs: ADRS) -> bytes:
    """Generate XMSS signature (Algorithm 9).

    Args:
        m: n-byte message.
        idx: Leaf index to sign with.

    Returns:
        XMSS signature: WOTS+ sig || auth path.
    """
    # Build authentication path
    auth = b""
    for j in range(params.hp):
        # Sibling index at height j: flip bit j of idx, then shift right by j
        s = (idx >> j) ^ 1
        auth += xmss_node(params, sk_seed, s, j, pk_seed, adrs)

    # Generate WOTS+ signature on m
    adrs.set_type(WOTS_HASH)
    adrs.set_key_pair_address(idx)
    sig = wots_sign(params, m, sk_seed, pk_seed, adrs)

    return sig + auth


def xmss_pk_from_sig(params: SLHDSAParams, idx: int, sig_xmss: bytes,
                     m: bytes, pk_seed: bytes, adrs: ADRS) -> bytes:
    """Compute XMSS root from signature (Algorithm 10).

    Args:
        idx: Leaf index.
        sig_xmss: XMSS signature (WOTS sig || auth path).
        m: n-byte message that was signed.

    Returns:
        Computed XMSS root node.
    """
    suite = get_suite(params.hash_type)
    n = params.n

    # Split signature
    wots_sig = sig_xmss[:params.wots_len * n]
    auth = sig_xmss[params.wots_len * n:]

    # Compute WOTS+ public key from signature
    adrs.set_type(WOTS_HASH)
    adrs.set_key_pair_address(idx)
    node = wots_pk_from_sig(params, wots_sig, m, pk_seed, adrs)

    # Climb auth path to compute root
    adrs.set_type(TREE)
    k = idx  # current node index tracking
    for j in range(params.hp):
        adrs.set_tree_height(j + 1)
        auth_j = auth[j * n:(j + 1) * n]
        parent = k >> 1
        adrs.set_tree_index(parent)
        if k % 2 == 0:
            node = suite.H(pk_seed, adrs, node + auth_j, n)
        else:
            node = suite.H(pk_seed, adrs, auth_j + node, n)
        k = parent

    return node
