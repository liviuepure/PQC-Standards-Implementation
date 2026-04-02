"""Reed-Solomon encode and decode over GF(256).

Systematic RS(n1, k) code with error-correction capability delta = (n1 - k) / 2.
Generator polynomial g(x) = prod_{i=1}^{2*delta} (x - alpha^i).

Encoding: systematic — codeword[i] for i=0..2*delta-1 are parity,
                        codeword[i] for i=2*delta..n1-1 are the message.
Decoding: Berlekamp-Massey + Chien search + Forney's formula.
"""

from hqc.gf256 import (
    gf256_add, gf256_mul, gf256_inv, gf256_pow, gf256_exp, gf256_log, gf256_div,
)
from hqc.params import HQCParams


def _build_generator_poly(delta: int) -> list:
    """Build the generator polynomial g(x) = prod_{i=1}^{2*delta} (x - alpha^i).

    Returns coefficients [g_0, g_1, ..., g_{2*delta}] where g_{2*delta} = 1.
    """
    two_delta = 2 * delta
    # Start with g(x) = 1
    g = [0] * (two_delta + 1)
    g[0] = 1

    for i in range(1, two_delta + 1):
        alpha_i = gf256_exp(i)
        # Multiply g by (x - alpha^i) = (x + alpha^i) in GF(256)
        new_g = [0] * (two_delta + 1)
        for j in range(i, 0, -1):
            new_g[j] = gf256_add(g[j - 1], gf256_mul(g[j], alpha_i))
        new_g[0] = gf256_mul(g[0], alpha_i)
        g = new_g

    return g


# Cache generator polynomials
_gen_poly_cache = {}


def _get_generator_poly(delta: int) -> list:
    """Get or compute the generator polynomial for given delta."""
    if delta not in _gen_poly_cache:
        _gen_poly_cache[delta] = _build_generator_poly(delta)
    return _gen_poly_cache[delta]


def rs_encode(msg: list, params: HQCParams) -> list:
    """Systematic RS encoding.

    Input: msg is a list of k GF(256) elements.
    Output: codeword of length n1 = k + 2*delta.

    The codeword polynomial is c(x) = m(x)*x^{2*delta} + r(x)
    where r(x) = m(x)*x^{2*delta} mod g(x).

    Codeword layout: [r_0, ..., r_{2d-1}, m_0, ..., m_{k-1}]
    (parity in low-degree positions, message in high-degree positions).
    """
    k = params.k
    n1 = params.n1
    two_delta = 2 * params.delta
    g = _get_generator_poly(params.delta)

    assert len(msg) == k

    # LFSR-based computation of r(x) = m(x)*x^{2*delta} mod g(x)
    # Process message coefficients from highest degree to lowest
    feedback = [0] * two_delta

    for i in range(k - 1, -1, -1):
        coeff = gf256_add(msg[i], feedback[two_delta - 1])
        for j in range(two_delta - 1, 0, -1):
            feedback[j] = gf256_add(feedback[j - 1], gf256_mul(g[j], coeff))
        feedback[0] = gf256_mul(g[0], coeff)

    # Codeword: [parity (2*delta) | message (k)]
    codeword = feedback + list(msg)
    return codeword


def rs_decode(received: list, params: HQCParams) -> tuple:
    """RS decoding using Berlekamp-Massey + Chien search + Forney's formula.

    Input: received is a list of n1 GF(256) elements.
    Output: (decoded_msg, success) where decoded_msg is k GF(256) elements.

    The message is in positions 2*delta..n1-1 of the codeword.
    Returns (msg, True) on success, (received[2*delta:], False) on failure.
    """
    n1 = params.n1
    k = params.k
    delta = params.delta
    two_delta = 2 * delta

    # Step 1: Compute syndromes S_i = received(alpha^i) for i = 1..2*delta
    syndromes = [0] * two_delta
    for i in range(two_delta):
        s = 0
        alpha_i = gf256_exp(i + 1)
        alpha_pow = 1  # alpha^(i+1)^0 = 1
        for j in range(n1):
            s = gf256_add(s, gf256_mul(received[j], alpha_pow))
            alpha_pow = gf256_mul(alpha_pow, alpha_i)
        syndromes[i] = s

    # Check if all syndromes are zero (no errors)
    if all(s == 0 for s in syndromes):
        return received[two_delta:], True

    # Step 2: Berlekamp-Massey algorithm to find error locator polynomial sigma(x)
    sigma = _berlekamp_massey(syndromes, two_delta)
    num_errors = len(sigma) - 1

    if num_errors > delta:
        return received[two_delta:], False

    # Step 3: Chien search to find error positions
    error_positions = _chien_search(sigma, n1)

    if len(error_positions) != num_errors:
        return received[two_delta:], False

    # Step 4: Forney's formula to compute error values
    omega = _compute_omega(syndromes, sigma, two_delta)

    # Compute error values
    corrected = list(received)
    for pos in error_positions:
        xj = gf256_exp(pos)
        xj_inv = gf256_inv(xj)

        # Evaluate omega(X_j^{-1})
        omega_val = 0
        xj_inv_pow = 1
        for i in range(len(omega)):
            omega_val = gf256_add(omega_val, gf256_mul(omega[i], xj_inv_pow))
            xj_inv_pow = gf256_mul(xj_inv_pow, xj_inv)

        # Evaluate sigma'(X_j^{-1}) -- formal derivative
        sigma_prime_val = 0
        xj_inv_pow = 1
        for i in range(1, len(sigma)):
            if i % 2 == 1:  # In GF(2), derivative only keeps odd-power terms
                sigma_prime_val = gf256_add(
                    sigma_prime_val,
                    gf256_mul(sigma[i], xj_inv_pow)
                )
            xj_inv_pow = gf256_mul(xj_inv_pow, xj_inv)

        if sigma_prime_val == 0:
            return received[two_delta:], False

        # Forney: e_j = omega(X_j^{-1}) / sigma'(X_j^{-1})
        error_val = gf256_mul(omega_val, gf256_inv(sigma_prime_val))
        corrected[pos] = gf256_add(corrected[pos], error_val)

    return corrected[two_delta:], True


def _berlekamp_massey(syndromes: list, two_delta: int) -> list:
    """Berlekamp-Massey algorithm to find the error locator polynomial.

    Returns sigma coefficients [sigma_0, sigma_1, ..., sigma_t] where sigma_0 = 1.
    """
    sigma = [1]
    old_sigma = [1]
    L = 0
    m = 1
    b = 1

    for n in range(two_delta):
        # Compute discrepancy
        d = syndromes[n]
        for i in range(1, len(sigma)):
            if n - i >= 0:
                d = gf256_add(d, gf256_mul(sigma[i], syndromes[n - i]))

        if d == 0:
            m += 1
        elif 2 * L <= n:
            temp = list(sigma)
            factor = gf256_mul(d, gf256_inv(b))
            new_len = max(len(sigma), len(old_sigma) + m)
            new_sigma = [0] * new_len
            for i in range(len(sigma)):
                new_sigma[i] = sigma[i]
            for i in range(len(old_sigma)):
                new_sigma[i + m] = gf256_add(new_sigma[i + m], gf256_mul(factor, old_sigma[i]))
            sigma = new_sigma
            old_sigma = temp
            L = n + 1 - L
            b = d
            m = 1
        else:
            factor = gf256_mul(d, gf256_inv(b))
            new_len = max(len(sigma), len(old_sigma) + m)
            new_sigma = [0] * new_len
            for i in range(len(sigma)):
                new_sigma[i] = sigma[i]
            for i in range(len(old_sigma)):
                new_sigma[i + m] = gf256_add(new_sigma[i + m], gf256_mul(factor, old_sigma[i]))
            sigma = new_sigma
            m += 1

    # Remove trailing zeros
    while len(sigma) > 1 and sigma[-1] == 0:
        sigma.pop()

    return sigma


def _chien_search(sigma: list, n: int) -> list:
    """Chien search: find positions j in [0,n) where sigma(alpha^{-j}) = 0."""
    positions = []
    for j in range(n):
        # Evaluate sigma at alpha^{-j}
        if j == 0:
            alpha_neg_j = 1
        else:
            alpha_neg_j = gf256_exp(255 - j) if j < 255 else gf256_exp(255 - (j % 255))

        val = 0
        power = 1
        for i in range(len(sigma)):
            val = gf256_add(val, gf256_mul(sigma[i], power))
            power = gf256_mul(power, alpha_neg_j)
        if val == 0:
            positions.append(j)
    return positions


def _compute_omega(syndromes: list, sigma: list, two_delta: int) -> list:
    """Compute error evaluator: omega(x) = S(x) * sigma(x) mod x^{two_delta}.

    S(x) = S[0] + S[1]*x + ... + S[2*delta-1]*x^{2*delta-1}
    """
    s_len = len(syndromes)
    sig_len = len(sigma)
    omega = [0] * two_delta

    for i in range(sig_len):
        for j in range(s_len):
            if i + j < two_delta:
                omega[i + j] = gf256_add(omega[i + j], gf256_mul(sigma[i], syndromes[j]))

    while len(omega) > 1 and omega[-1] == 0:
        omega.pop()

    return omega
