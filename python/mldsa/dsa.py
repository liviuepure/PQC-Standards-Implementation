"""ML-DSA digital signature algorithm (FIPS 204).

Implements key generation, signing, and verification.
"""

import os

from mldsa.field import Q, field_add, field_sub
from mldsa.ntt import ntt, ntt_inverse, pointwise_mul
from mldsa.params import MLDSAParams
from mldsa.hash_funcs import (
    h, expand_a, expand_s, expand_mask, sample_in_ball,
)
from mldsa.decompose import power2_round, high_bits, low_bits, make_hint, use_hint
from mldsa.encode import (
    encode_pk, decode_pk, encode_sk, decode_sk,
    encode_w1, encode_sig, decode_sig,
)


def _poly_add(a: list[int], b: list[int]) -> list[int]:
    """Add two polynomials coefficient-wise mod Q."""
    return [field_add(a[i], b[i]) for i in range(256)]


def _poly_sub(a: list[int], b: list[int]) -> list[int]:
    """Subtract two polynomials coefficient-wise mod Q."""
    return [field_sub(a[i], b[i]) for i in range(256)]


def _vec_ntt(v: list[list[int]]) -> list[list[int]]:
    """Apply NTT to each polynomial in a vector."""
    return [ntt(p) for p in v]


def _vec_ntt_inv(v: list[list[int]]) -> list[list[int]]:
    """Apply inverse NTT to each polynomial in a vector."""
    return [ntt_inverse(p) for p in v]


def _mat_vec_mul(A_hat: list[list[list[int]]], v_hat: list[list[int]]) -> list[list[int]]:
    """Multiply matrix A_hat (in NTT domain) by vector v_hat (in NTT domain).

    A_hat is k x l, v_hat has l polynomials. Result has k polynomials.
    """
    k = len(A_hat)
    l = len(v_hat)
    result = []
    for i in range(k):
        acc = [0] * 256
        for j in range(l):
            prod = pointwise_mul(A_hat[i][j], v_hat[j])
            acc = [field_add(acc[m], prod[m]) for m in range(256)]
        result.append(acc)
    return result


def _center(val: int) -> int:
    """Center a value from [0, Q) to [-(Q-1)/2, (Q-1)/2]."""
    val = val % Q
    if val > Q // 2:
        return val - Q
    return val


def _poly_inf_norm(poly: list[int]) -> int:
    """Compute infinity norm of a polynomial (centered representation)."""
    max_val = 0
    for c in poly:
        val = abs(_center(c))
        if val > max_val:
            max_val = val
    return max_val


def _vec_inf_norm(v: list[list[int]]) -> int:
    """Compute infinity norm of a vector of polynomials."""
    return max(_poly_inf_norm(p) for p in v)


def keygen(params: MLDSAParams) -> tuple[bytes, bytes]:
    """ML-DSA key generation (FIPS 204 Algorithm 1).

    Returns (pk, sk) as byte strings.
    """
    # Step 1: Generate random seed
    xi = os.urandom(32)

    # Step 2: Expand seed into (rho, rho_prime, K)
    expanded = h(xi + bytes([params.k]) + bytes([params.l]), 128)
    rho = expanded[:32]
    rho_prime = expanded[32:96]
    K = expanded[96:128]

    # Step 3: Expand matrix A_hat from rho
    A_hat = expand_a(rho, params.k, params.l)

    # Step 4: Expand secret vectors s1, s2
    s1, s2 = expand_s(rho_prime, params.l, params.k, params.eta)

    # Step 5: Compute t = A * s1 + s2
    s1_hat = _vec_ntt(s1)
    t_hat = _mat_vec_mul(A_hat, s1_hat)
    t = _vec_ntt_inv(t_hat)

    # Add s2 to t
    for i in range(params.k):
        t[i] = _poly_add(t[i], s2[i])

    # Step 6: Power2Round on t
    t1 = []
    t0 = []
    for i in range(params.k):
        t1_poly = []
        t0_poly = []
        for j in range(256):
            r1, r0 = power2_round(t[i][j])
            t1_poly.append(r1)
            t0_poly.append(r0)
        t1.append(t1_poly)
        t0.append(t0_poly)

    # Step 7: Encode public key and secret key
    pk = encode_pk(rho, t1, params)

    # tr = H(pk) using SHAKE-256 with 64 bytes output
    tr = h(pk, 64)

    sk = encode_sk(rho, K, tr, s1, s2, t0, params)

    return pk, sk


def sign(sk: bytes, msg: bytes, params: MLDSAParams) -> bytes:
    """ML-DSA signing (FIPS 204 Algorithm 2).

    Returns signature as byte string.
    Uses rejection sampling loop with 4 abort conditions.
    """
    # Decode secret key
    rho, K, tr, s1, s2, t0 = decode_sk(sk, params)

    # Expand A_hat
    A_hat = expand_a(rho, params.k, params.l)

    # Precompute NTT of secret vectors
    s1_hat = _vec_ntt(s1)
    s2_hat = _vec_ntt(s2)
    t0_hat = _vec_ntt(t0)

    # mu = H(tr || msg, 64)
    mu = h(tr + msg, 64)

    # rho_prime = H(K || mu, 64) -- deterministic signing
    rho_prime = h(K + mu, 64)

    alpha = 2 * params.gamma2
    kappa = 0

    # Rejection sampling loop
    while True:
        # Step 1: Expand mask y
        y = expand_mask(rho_prime, kappa, params.l, params.gamma1)
        kappa += params.l

        # Step 2: w = A * NTT(y)
        y_hat = _vec_ntt(y)
        w_hat = _mat_vec_mul(A_hat, y_hat)
        w = _vec_ntt_inv(w_hat)

        # Step 3: Decompose w
        w1 = []
        for i in range(params.k):
            w1_poly = [high_bits(w[i][j], alpha) for j in range(256)]
            w1.append(w1_poly)

        # Step 4: Challenge hash
        w1_encoded = encode_w1(w1, params)
        c_tilde = h(mu + w1_encoded, params.lambda_ // 4)
        c = sample_in_ball(c_tilde, params.tau)

        # Step 5: Compute z = y + c*s1 (via NTT)
        c_hat = ntt(c)
        cs1_hat = [pointwise_mul(c_hat, s1_hat[i]) for i in range(params.l)]
        cs1 = _vec_ntt_inv(cs1_hat)

        z = []
        for i in range(params.l):
            z.append(_poly_add(y[i], cs1[i]))

        # Step 6: Compute r = w - c*s2
        cs2_hat = [pointwise_mul(c_hat, s2_hat[i]) for i in range(params.k)]
        cs2 = _vec_ntt_inv(cs2_hat)

        r = []
        for i in range(params.k):
            r.append(_poly_sub(w[i], cs2[i]))

        # Condition 1: ||z||_inf >= gamma1 - beta
        if _vec_inf_norm(z) >= params.gamma1 - params.beta:
            continue

        # Condition 2: ||r0||_inf >= gamma2 - beta where r0 = LowBits(r)
        r0_vec = []
        for i in range(params.k):
            r0_poly = [low_bits(r[i][j], alpha) for j in range(256)]
            r0_vec.append(r0_poly)

        if _vec_inf_norm(r0_vec) >= params.gamma2 - params.beta:
            continue

        # Step 7: Compute hints
        ct0_hat = [pointwise_mul(c_hat, t0_hat[i]) for i in range(params.k)]
        ct0 = _vec_ntt_inv(ct0_hat)

        # Condition 3: ||c*t0||_inf >= gamma2
        if _vec_inf_norm(ct0) >= params.gamma2:
            continue

        # Make hints: MakeHint(-ct0, w - cs2 + ct0) per FIPS 204
        hints = []
        total_hints = 0
        for i in range(params.k):
            hint_poly = [0] * 256
            for j in range(256):
                neg_ct0_j = (Q - ct0[i][j]) % Q
                r_plus_ct0 = (r[i][j] + ct0[i][j]) % Q
                hint_poly[j] = make_hint(neg_ct0_j, r_plus_ct0, alpha)
                total_hints += hint_poly[j]
            hints.append(hint_poly)

        # Condition 4: number of hints > omega
        if total_hints > params.omega:
            continue

        # Center z coefficients for encoding
        z_centered = []
        for poly in z:
            z_centered.append([_center(c) for c in poly])

        # Encode and return signature
        sig = encode_sig(c_tilde, z_centered, hints, params)
        return sig


def verify(pk: bytes, msg: bytes, sig: bytes, params: MLDSAParams) -> bool:
    """ML-DSA verification (FIPS 204 Algorithm 3).

    Returns True if the signature is valid, False otherwise.
    """
    # Decode public key
    rho, t1 = decode_pk(pk, params)

    # Decode signature
    c_tilde_len = params.lambda_ // 4
    if len(sig) != params.sig_size:
        return False

    try:
        c_tilde, z_signed, hints = decode_sig(sig, params)
    except (IndexError, ValueError):
        return False

    # Check z infinity norm (z_signed has signed coefficients)
    if _vec_inf_norm(z_signed) >= params.gamma1 - params.beta:
        return False

    # Convert z to mod Q representation for NTT
    z = [[c % Q for c in poly] for poly in z_signed]

    # Count hints
    total_hints = sum(sum(h_poly) for h_poly in hints)
    if total_hints > params.omega:
        return False

    # Expand A_hat
    A_hat = expand_a(rho, params.k, params.l)

    # tr = H(pk, 64)
    tr = h(pk, 64)

    # mu = H(tr || msg, 64)
    mu = h(tr + msg, 64)

    # Reconstruct c
    c = sample_in_ball(c_tilde, params.tau)
    c_hat = ntt(c)

    # Compute A*z - c*t1*2^d (all in NTT domain)
    z_hat = _vec_ntt(z)
    Az_hat = _mat_vec_mul(A_hat, z_hat)

    # t1 * 2^d in NTT domain
    d = params.d
    t1_scaled = []
    for i in range(params.k):
        poly = [(t1[i][j] * (1 << d)) % Q for j in range(256)]
        t1_scaled.append(poly)
    t1_hat = _vec_ntt(t1_scaled)

    # c * t1 * 2^d
    ct1_hat = [pointwise_mul(c_hat, t1_hat[i]) for i in range(params.k)]

    # w'_approx = A*z - c*t1*2^d (in NTT domain, then inverse)
    w_prime_hat = []
    for i in range(params.k):
        poly = [field_sub(Az_hat[i][j], ct1_hat[i][j]) for j in range(256)]
        w_prime_hat.append(poly)
    w_prime = _vec_ntt_inv(w_prime_hat)

    # Apply hints to get w1'
    alpha = 2 * params.gamma2
    w1_prime = []
    for i in range(params.k):
        w1_poly = [use_hint(hints[i][j], w_prime[i][j], alpha) for j in range(256)]
        w1_prime.append(w1_poly)

    # Recompute challenge hash
    w1_encoded = encode_w1(w1_prime, params)
    c_tilde_prime = h(mu + w1_encoded, params.lambda_ // 4)

    return c_tilde == c_tilde_prime
