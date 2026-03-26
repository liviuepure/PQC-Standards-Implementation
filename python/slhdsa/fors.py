"""FORS (Forest of Random Subsets) for SLH-DSA per FIPS 205, Section 7."""

from slhdsa.params import SLHDSAParams
from slhdsa.address import ADRS, FORS_TREE, FORS_ROOTS, FORS_PRF
from slhdsa.hash_funcs import get_suite
from slhdsa.utils import base_2b


def fors_skgen(params: SLHDSAParams, sk_seed: bytes, pk_seed: bytes,
               adrs: ADRS, idx: int) -> bytes:
    """Generate FORS secret key value (Algorithm 14)."""
    suite = get_suite(params.hash_type)
    sk_adrs = adrs.copy()
    sk_adrs.set_type(FORS_PRF)
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    sk_adrs.set_tree_index(idx)
    return suite.PRF(pk_seed, sk_seed, sk_adrs, params.n)


def fors_node(params: SLHDSAParams, sk_seed: bytes, i: int, z: int,
              pk_seed: bytes, adrs: ADRS) -> bytes:
    """Compute FORS tree node (Algorithm 15).

    Args:
        i: Node index at height z.
        z: Height in the FORS tree.
    """
    suite = get_suite(params.hash_type)

    if z == 0:
        sk = fors_skgen(params, sk_seed, pk_seed, adrs, i)
        adrs_t = adrs.copy()
        adrs_t.set_type(FORS_TREE)
        adrs_t.set_key_pair_address(adrs.get_key_pair_address())
        adrs_t.set_tree_height(0)
        adrs_t.set_tree_index(i)
        return suite.F(pk_seed, adrs_t, sk, params.n)
    else:
        lnode = fors_node(params, sk_seed, 2 * i, z - 1, pk_seed, adrs)
        rnode = fors_node(params, sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)
        adrs_t = adrs.copy()
        adrs_t.set_type(FORS_TREE)
        adrs_t.set_key_pair_address(adrs.get_key_pair_address())
        adrs_t.set_tree_height(z)
        adrs_t.set_tree_index(i)
        return suite.H(pk_seed, adrs_t, lnode + rnode, params.n)


def fors_sign(params: SLHDSAParams, md: bytes, sk_seed: bytes,
              pk_seed: bytes, adrs: ADRS) -> bytes:
    """Generate FORS signature (Algorithm 16).

    Args:
        md: Message digest of length ceil(k*a / 8) bytes.

    Returns:
        FORS signature: for each tree i, sk_value || auth[0] || ... || auth[a-1].
    """
    sig_fors = b""
    indices = base_2b(md, params.a, params.k)

    for i in range(params.k):
        idx = indices[i]
        # Absolute leaf index within the FORS forest
        abs_idx = i * (1 << params.a) + idx

        # Append secret value
        sig_fors += fors_skgen(params, sk_seed, pk_seed, adrs, abs_idx)

        # Authentication path for tree i
        for j in range(params.a):
            # Sibling node index at height j
            # Parent of abs_idx at height j is abs_idx >> (j+1) at height j+1
            # Sibling of the node at height j is obtained by flipping bit j of abs_idx
            s = (abs_idx >> (j + 1)) * 2 + (1 - ((abs_idx >> j) & 1))
            sig_fors += fors_node(params, sk_seed, s, j, pk_seed, adrs)

    return sig_fors


def fors_pk_from_sig(params: SLHDSAParams, sig_fors: bytes, md: bytes,
                     pk_seed: bytes, adrs: ADRS) -> bytes:
    """Compute FORS public key from signature (Algorithm 17).

    Args:
        sig_fors: FORS signature.
        md: Message digest.

    Returns:
        FORS public key (n bytes).
    """
    suite = get_suite(params.hash_type)
    indices = base_2b(md, params.a, params.k)
    n = params.n

    roots = b""
    offset = 0

    for i in range(params.k):
        idx = indices[i]
        abs_idx = i * (1 << params.a) + idx

        # Recover leaf from secret value
        sk = sig_fors[offset:offset + n]
        offset += n

        adrs_t = adrs.copy()
        adrs_t.set_type(FORS_TREE)
        adrs_t.set_key_pair_address(adrs.get_key_pair_address())
        adrs_t.set_tree_height(0)
        adrs_t.set_tree_index(abs_idx)
        node = suite.F(pk_seed, adrs_t, sk, n)

        # Climb authentication path
        for j in range(params.a):
            auth_j = sig_fors[offset:offset + n]
            offset += n

            adrs_t.set_tree_height(j + 1)
            parent_idx = abs_idx >> (j + 1)
            adrs_t.set_tree_index(parent_idx)
            if ((abs_idx >> j) & 1) == 0:
                node = suite.H(pk_seed, adrs_t, node + auth_j, n)
            else:
                node = suite.H(pk_seed, adrs_t, auth_j + node, n)

        roots += node

    # Compress FORS roots
    fors_pk_adrs = adrs.copy()
    fors_pk_adrs.set_type(FORS_ROOTS)
    fors_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    pk = suite.T(pk_seed, fors_pk_adrs, roots, n)
    return pk
