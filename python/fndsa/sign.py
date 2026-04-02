"""FN-DSA signing (FIPS 206).

Implements:
  - hash_to_point: hash a message to a polynomial in Z_q[x]/(x^n+1)
  - ff_sampling_babai: Babai nearest-plane lattice sampler (NOT FIPS 206 Algorithm 11)
  - sign_internal: full signing with norm-bound retry loop

# NOTE: NOT FIPS 206 Algorithm 11 — Babai nearest-plane, suitable for correctness testing only.
# A production implementation must replace ff_sampling_babai with the recursive FIPS 206
# ffSampling algorithm using the Gram-Schmidt ffTree and RCDT-based Gaussian sampler.
"""
import hashlib
import math

from .params import Params, Q
from .encode import decode_sk, encode_sig
from .ntt import poly_mul_ntt, poly_inv_ntt, ntt as _ntt, intt as _intt
from .fft import fft as _fft, ifft as _ifft


def hash_to_point(msg: bytes, params: Params) -> list[int]:
    """Hash msg (salt||message) to a polynomial c in Z_q[x]/(x^n+1).

    Uses SHAKE-256 extended output with rejection sampling on 16-bit values.
    Discards values >= 5*Q for near-uniform distribution mod Q.
    Mirrors Go HashToPoint.
    """
    n = params.n
    out = [0] * n
    h = hashlib.shake_256(msg)

    # Use XOF (extendable output function) mode
    # We generate pairs of bytes until we have n coefficients
    # SHAKE-256 XOF: generate output in chunks
    buf_size = 2 * n * 2  # generous initial buffer
    raw = h.digest(buf_size)
    pos = 0
    count = 0

    while count < n:
        if pos + 2 > len(raw):
            # Need more bytes - extend the buffer
            buf_size *= 2
            raw = hashlib.shake_256(msg).digest(buf_size)

        v = raw[pos] | (raw[pos + 1] << 8)
        pos += 2
        # Rejection: discard values >= 5*Q for near-uniform mod Q
        if v < 5 * Q:
            out[count] = v % Q
            count += 1

    return out


def _center_mod_q(v: int) -> int:
    """Reduce v mod Q and center in (-Q/2, Q/2]."""
    v = ((v % Q) + Q) % Q
    if v > Q // 2:
        v -= Q
    return v


def _poly_to_fft(a: list[int], n: int) -> list[complex]:
    """Convert integer polynomial to FFT domain."""
    return _fft([complex(v) for v in a], n)


def _round_fft_to_ints(f_fft: list[complex], n: int) -> list[int]:
    """Apply IFFT and round to nearest integer polynomial."""
    tmp = _ifft(list(f_fft), n)
    return [round(v.real) for v in tmp]


def _recover_g(f: list[int], g: list[int], F: list[int], n: int) -> list[int] | None:
    """Recover G from (f, g, F) using the NTRU equation f*G - g*F = Q.

    From the equation: f*G ≡ g*F (mod q), so G ≡ g*F*f^{-1} (mod q).
    Centers coefficients in (-Q/2, Q/2] to recover exact integer values.

    Returns G or None if f is not invertible mod q (corrupt key).
    """
    g_mod_q = [((v % Q) + Q) % Q for v in g]
    F_mod_q = [((v % Q) + Q) % Q for v in F]

    # Compute g*F mod q
    gF = poly_mul_ntt(g_mod_q, F_mod_q, n)

    # Compute f^{-1} mod q
    f_mod_q = [((v % Q) + Q) % Q for v in f]
    f_ntt_vals = _ntt(f_mod_q, n)
    if any(v == 0 for v in f_ntt_vals):
        return None  # f not invertible mod q

    f_inv_ntt = [pow(v, Q - 2, Q) for v in f_ntt_vals]
    f_inv = _intt(f_inv_ntt, n)

    # G = g*F*f^{-1} mod q, then center
    G = poly_mul_ntt(gF, f_inv, n)
    return [_center_mod_q(v) for v in G]


def _norm_sq(s1: list[int], s2: list[int]) -> int:
    """Compute squared Euclidean norm of (s1, s2)."""
    return sum(v * v for v in s1) + sum(v * v for v in s2)


def ff_sampling_babai(c: list[int], f: list[int], g: list[int],
                      F: list[int], G: list[int], n: int) -> tuple:
    """Babai nearest-plane sampler for FN-DSA signing.

    # NOTE: NOT FIPS 206 Algorithm 11 — Babai nearest-plane, suitable for
    # correctness testing only. Not suitable for production use due to lack of
    # proper Gaussian distribution and side-channel resistance.

    Finds the lattice vector v in NTRU coset L = {(a,b): a + b*h = 0 mod q}
    closest to target (c, 0) using two-step Gram-Schmidt nearest-plane.

    Returns (s1, s2) where s1 = c - v1, s2 = -v2, satisfying s1*h + s2 = c mod q.

    Mirrors Go ffSamplingBabai.
    """
    c_fft = _poly_to_fft(c, n)
    f_fft = _poly_to_fft(f, n)
    g_fft = _poly_to_fft(g, n)
    F_fft = _poly_to_fft(F, n)
    G_fft = _poly_to_fft(G, n)

    # Gram-Schmidt: compute b1* = b1 - mu10*b0* per FFT point
    # b0 = (g, -f), b1 = (G, -F)
    # mu10_j = <b1_j, b0_j^*> / ||b0_j^*||^2
    #        = (G_j*conj(g_j) + F_j*conj(f_j)) / (|g_j|^2 + |f_j|^2)
    b1_star_fft = [(0j, 0j)] * n
    b1_star_norm_sq = [0.0] * n
    for j in range(n):
        gj = g_fft[j]
        fj = f_fft[j]
        Gj = G_fft[j]
        Fj = F_fft[j]
        b0_norm_sq = (gj * gj.conjugate()).real + (fj * fj.conjugate()).real
        mu10 = 0j
        if b0_norm_sq != 0:
            num = Gj * gj.conjugate() + Fj * fj.conjugate()
            mu10 = complex(num.real / b0_norm_sq, num.imag / b0_norm_sq)
        b1s0 = Gj - mu10 * gj
        b1s1 = -Fj + mu10 * fj
        b1_star_fft[j] = (b1s0, b1s1)
        b1_star_norm_sq[j] = (b1s0 * b1s0.conjugate()).real + (b1s1 * b1s1.conjugate()).real

    # Step 1: project (c_j, 0) along b1*_j
    # tau1_j = <(c_j, 0), conj(b1*_j)> / ||b1*||^2
    #        = c_j * conj(b1*_j[0]) / ||b1*||^2
    tau1_fft = [0j] * n
    for j in range(n):
        b1s_norm = b1_star_norm_sq[j]
        if b1s_norm != 0:
            b1s0 = b1_star_fft[j][0]
            num = c_fft[j] * b1s0.conjugate()
            tau1_fft[j] = complex(num.real / b1s_norm, num.imag / b1s_norm)

    z1 = _round_fft_to_ints(tau1_fft, n)
    z1_fft = _poly_to_fft(z1, n)

    # Update target: t'_j = (c_j, 0) - z1_j*(G_j, -F_j) = (c_j - z1_j*G_j, z1_j*F_j)
    c_prime_fft = [0j] * n
    x_prime_fft = [0j] * n
    for j in range(n):
        c_prime_fft[j] = c_fft[j] - z1_fft[j] * G_fft[j]
        x_prime_fft[j] = z1_fft[j] * F_fft[j]

    # Step 2: project t'_j along b0*_j = (g_j, -f_j)
    # tau0_j = <(c'_j, x'_j), conj((g_j, -f_j))> / (|g_j|^2 + |f_j|^2)
    #        = (c'_j*conj(g_j) - x'_j*conj(f_j)) / (|g_j|^2 + |f_j|^2)
    tau0_fft = [0j] * n
    for j in range(n):
        gj = g_fft[j]
        fj = f_fft[j]
        b0_norm_sq = (gj * gj.conjugate()).real + (fj * fj.conjugate()).real
        if b0_norm_sq != 0:
            num = c_prime_fft[j] * gj.conjugate() - x_prime_fft[j] * fj.conjugate()
            tau0_fft[j] = complex(num.real / b0_norm_sq, num.imag / b0_norm_sq)

    z0 = _round_fft_to_ints(tau0_fft, n)
    z0_fft = _poly_to_fft(z0, n)

    # Lattice vector v = z0*b0 + z1*b1
    # v1_j = z0_j*g_j + z1_j*G_j
    # v2_j = -z0_j*f_j - z1_j*F_j
    #
    # Signature: (c, 0) - v
    # s1_j = z0_j*f_j + z1_j*F_j  (multiplied by h in verification)
    # s2_j = c_j - z0_j*g_j - z1_j*G_j
    s1_fft = [0j] * n
    s2_fft = [0j] * n
    for j in range(n):
        s1_fft[j] = z0_fft[j] * f_fft[j] + z1_fft[j] * F_fft[j]
        s2_fft[j] = c_fft[j] - z0_fft[j] * g_fft[j] - z1_fft[j] * G_fft[j]

    s1_raw = _round_fft_to_ints(s1_fft, n)
    s2_raw = _round_fft_to_ints(s2_fft, n)

    s1 = [_center_mod_q(v) for v in s1_raw]
    s2 = [_center_mod_q(v) for v in s2_raw]
    return s1, s2


def sign_internal(sk: bytes, msg: bytes, params: Params, rng=None) -> bytes:
    """Sign msg using secret key sk under parameter set params.

    Generates a random 40-byte salt, hashes salt||msg to a target polynomial,
    runs Babai nearest-plane sampling, and retries until norm bound is met.

    Returns encoded signature bytes.
    """
    import os
    if rng is None:
        rng = os.urandom

    result = decode_sk(sk, params)
    if result is None:
        raise ValueError("fndsa: invalid secret key")
    f, g, F = result

    n = params.n

    # Recover G from (f, g, F) via the NTRU equation
    G = _recover_g(f, g, F, n)
    if G is None:
        raise ValueError("fndsa: invalid secret key: f is not invertible mod q")

    # Pre-compute h = g*f^{-1} mod q (for verification check during signing)
    f_mod_q = [((v % Q) + Q) % Q for v in f]
    g_mod_q = [((v % Q) + Q) % Q for v in g]
    h = poly_inv_ntt(f_mod_q, n)
    h = poly_mul_ntt(g_mod_q, h, n)

    for attempt in range(1000):
        # Sample fresh 40-byte salt
        salt = rng(40)

        # Compute target c = HashToPoint(salt || msg)
        hash_input = salt + msg
        c = hash_to_point(hash_input, params)

        # Center c in (-Q/2, Q/2] for FFT arithmetic
        c_centered = [_center_mod_q(v) for v in c]

        # Run Babai nearest-plane to get (s1, s2)
        s1, s2 = ff_sampling_babai(c_centered, f, g, F, G, n)

        # Verify that s1*h + s2 ≡ c (mod q) — the FN-DSA verification equation
        s1_mod_q = [((v % Q) + Q) % Q for v in s1]
        s1h = poly_mul_ntt(s1_mod_q, h, n)
        valid = True
        for i in range(n):
            total = ((s1h[i] + s2[i]) % Q + Q) % Q
            if total != c[i]:
                valid = False
                break
        if not valid:
            continue

        # Check norm bound
        ns = _norm_sq(s1, s2)
        if ns > params.beta_sq:
            continue

        # Encode signature
        sig = encode_sig(salt, s1, params)
        if sig is None:
            # Compressed s1 too large; retry with new salt
            continue

        return sig

    raise RuntimeError("fndsa: signing failed: could not produce valid signature in 1000 attempts")
