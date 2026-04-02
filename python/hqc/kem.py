"""HQC KEM: Key Generation, Encapsulation, Decapsulation.

Based on the NIST HQC specification.

Public key: pk = seed_pk (40 bytes) || s_bytes (ceil(n/8) bytes)
  where h = Expand(seed_pk) and s = x + h*y mod (x^n - 1)

Secret key: sk = seed_sk (40 bytes) || pk
  where seed_sk is used to derive x, y, and seed_pk

Ciphertext: ct = u_bytes || v_bytes || salt (64 bytes)
  where u = r1 + h*r2, v = m_enc + s*r2 + e

Shared secret: ss = SHAKE-256(m || ct, 64)
"""

import hashlib
import os

from hqc.params import HQCParams
from hqc.gf2 import (
    gf2_add, gf2_mul_mod, gf2_to_bytes, gf2_from_bytes, gf2_set_bit,
    gf2_weight,
)
from hqc.tensor import tensor_encode, tensor_decode


SEED_BYTES = 40
SALT_BYTES = 64
SS_BYTES = 64


def _shake256(data: bytes, length: int) -> bytes:
    """SHAKE-256 squeeze."""
    return hashlib.shake_256(data).digest(length)


def _expand_h(seed_pk: bytes, n: int) -> int:
    """Expand seed_pk into a dense GF(2) polynomial h of degree < n."""
    num_bytes = (n + 7) // 8
    data = _shake256(seed_pk, num_bytes)
    return gf2_from_bytes(data, n)


def _expand_seed_to_fixed_weight(data: bytes, offset: int, n: int, w: int) -> tuple:
    """Generate a GF(2) polynomial with exactly w nonzero coefficients.

    Uses rejection sampling from sequential 4-byte chunks.
    Returns (polynomial, new_offset).
    """
    positions = []
    seen = set()
    while len(positions) < w:
        if offset + 4 > len(data):
            raise ValueError("Not enough data for fixed-weight polynomial")
        val = int.from_bytes(data[offset:offset+4], byteorder='little')
        offset += 4
        pos = val % n
        if pos not in seen:
            seen.add(pos)
            positions.append(pos)
    result = 0
    for pos in positions:
        result = gf2_set_bit(result, pos)
    return result, offset


def _serialize_poly(poly: int, n: int) -> bytes:
    """Serialize a GF(2) polynomial to ceil(n/8) bytes."""
    return gf2_to_bytes(poly, n)


def _deserialize_poly(data: bytes, n: int) -> int:
    """Deserialize a GF(2) polynomial from bytes."""
    return gf2_from_bytes(data, n)


def key_gen(params: HQCParams) -> tuple:
    """Generate an HQC key pair.

    Returns: (pk: bytes, sk: bytes)
      pk = seed_pk || s_bytes
      sk = seed_sk || pk
    """
    n = params.n
    w = params.w
    n_bytes = (n + 7) // 8

    # Generate master seed
    seed_sk = os.urandom(SEED_BYTES)

    # Derive seed_pk, x, y from seed_sk
    # We expand seed_sk to get: seed_pk (40 bytes), then x and y positions
    expand_len = SEED_BYTES + w * 8 + w * 8  # generous
    expanded = _shake256(seed_sk, expand_len)

    seed_pk = expanded[:SEED_BYTES]
    offset = SEED_BYTES

    x, offset = _expand_seed_to_fixed_weight(expanded, offset, n, w)
    y, offset = _expand_seed_to_fixed_weight(expanded, offset, n, w)

    # Expand h from seed_pk
    h = _expand_h(seed_pk, n)

    # Compute s = x + h*y mod (x^n - 1)
    hy = gf2_mul_mod(h, y, n)
    s = gf2_add(x, hy)

    # Serialize
    s_bytes = _serialize_poly(s, n)
    pk = seed_pk + s_bytes
    assert len(pk) == params.pk_size, f"pk size mismatch: {len(pk)} != {params.pk_size}"

    sk = seed_sk + pk
    assert len(sk) == params.sk_size, f"sk size mismatch: {len(sk)} != {params.sk_size}"

    return pk, sk


def _encaps_internal(pk: bytes, m: bytes, salt: bytes, params: HQCParams) -> tuple:
    """Internal encapsulation (deterministic given m and salt).

    Returns: (ct, u, v, r1, r2, e) for verification purposes.
    """
    n = params.n
    n1n2 = params.n1n2
    wr = params.wr
    we = params.we
    n_bytes = (n + 7) // 8
    n1n2_bytes = (n1n2 + 7) // 8

    # Parse pk
    seed_pk = pk[:SEED_BYTES]
    s = _deserialize_poly(pk[SEED_BYTES:], n)
    h = _expand_h(seed_pk, n)

    # Derive theta from (m || salt || pk) using SHAKE-256
    theta_seed = m + salt + pk
    theta_len = wr * 8 + wr * 8 + we * 8  # generous
    theta_data = _shake256(theta_seed, theta_len)

    offset = 0
    r1, offset = _expand_seed_to_fixed_weight(theta_data, offset, n, wr)
    r2, offset = _expand_seed_to_fixed_weight(theta_data, offset, n, wr)
    e, offset = _expand_seed_to_fixed_weight(theta_data, offset, n1n2, we)

    # u = r1 + h*r2 mod (x^n - 1)
    hr2 = gf2_mul_mod(h, r2, n)
    u = gf2_add(r1, hr2)

    # Encode message
    m_enc = tensor_encode(m, params)

    # v = m_enc + s*r2 + e
    # s*r2 mod (x^n - 1), truncated to n1n2 bits
    sr2 = gf2_mul_mod(s, r2, n)
    sr2_trunc = sr2 & ((1 << n1n2) - 1)
    v = gf2_add(m_enc, gf2_add(sr2_trunc, e))

    # Serialize ciphertext: u || v || salt
    u_bytes = _serialize_poly(u, n)
    v_bytes = _serialize_poly(v, n1n2)
    ct = u_bytes + v_bytes + salt

    assert len(ct) == params.ct_size, f"ct size mismatch: {len(ct)} != {params.ct_size}"

    return ct, u, v


def encaps(pk: bytes, params: HQCParams) -> tuple:
    """Encapsulate: generate a shared secret and ciphertext.

    Returns: (ct: bytes, ss: bytes)
    """
    k = params.k

    # Generate random message and salt
    m = os.urandom(k)
    salt = os.urandom(SALT_BYTES)

    ct, _, _ = _encaps_internal(pk, m, salt, params)

    # Shared secret
    ss = _shake256(m + ct, SS_BYTES)

    return ct, ss


def decaps(sk: bytes, ct: bytes, params: HQCParams) -> bytes:
    """Decapsulate: recover shared secret from secret key and ciphertext.

    Returns: ss: bytes (64 bytes)
    """
    n = params.n
    n1n2 = params.n1n2
    w = params.w
    k = params.k
    n_bytes = (n + 7) // 8
    n1n2_bytes = (n1n2 + 7) // 8

    # Parse sk: seed_sk || pk
    seed_sk = sk[:SEED_BYTES]
    pk = sk[SEED_BYTES:]

    # Re-derive x, y from seed_sk
    expand_len = SEED_BYTES + w * 8 + w * 8
    expanded = _shake256(seed_sk, expand_len)
    offset = SEED_BYTES
    x, offset = _expand_seed_to_fixed_weight(expanded, offset, n, w)
    y, offset = _expand_seed_to_fixed_weight(expanded, offset, n, w)

    # Parse ciphertext: u || v || salt
    u = _deserialize_poly(ct[:n_bytes], n)
    v = _deserialize_poly(ct[n_bytes:n_bytes + n1n2_bytes], n1n2)
    salt = ct[n_bytes + n1n2_bytes:n_bytes + n1n2_bytes + SALT_BYTES]

    # Compute noisy = v + u*y (in GF(2), subtraction = addition)
    uy = gf2_mul_mod(u, y, n)
    uy_trunc = uy & ((1 << n1n2) - 1)
    noisy = gf2_add(v, uy_trunc)

    # Decode message
    m_prime, decode_ok = tensor_decode(noisy, params)

    # Re-encapsulate with m_prime to verify
    ct_prime, _, _ = _encaps_internal(pk, m_prime, salt, params)

    # FO check
    if ct == ct_prime:
        # Success
        ss = _shake256(m_prime + ct, SS_BYTES)
    else:
        # Rejection: use seed_sk as the secret
        ss = _shake256(seed_sk + ct, SS_BYTES)

    return ss
