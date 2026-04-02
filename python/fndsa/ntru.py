"""NTRU key generation for FN-DSA (FIPS 206 Algorithm 5).

Implements recursive NTRU equation solver over Z[x]/(x^n+1).
Uses Python's arbitrary-precision integers throughout for exact arithmetic.

Algorithm:
1. Sample f, g from D_{Z, sigma} where sigma = 1.17 * sqrt(Q / (2n))
2. Check f is invertible mod 2 and mod q, and norm bound is satisfied
3. Solve f*G - g*F = Q over Z[x]/(x^n+1) using recursive field norm
4. Babai reduce (F, G) using (f, g) basis
5. Verify f*G - g*F = Q exactly
"""
import math
import sys

# Ensure sufficient recursion depth for the NTRU recursive solver.
# At n=1024, the recursion goes ~10 levels deep but each level involves
# significant Python call overhead (poly_mul_int_z, etc.).
_REQUIRED_RECURSION_LIMIT = 5000
if sys.getrecursionlimit() < _REQUIRED_RECURSION_LIMIT:
    sys.setrecursionlimit(_REQUIRED_RECURSION_LIMIT)

from .params import Params, Q
from .gaussian import sample_gaussian
from .ntt import ntt as _ntt


def _ntru_sigma(n: int) -> float:
    """Compute sigma = 1.17 * sqrt(Q / (2n))."""
    return 1.17 * math.sqrt(Q / (2 * n))


def _poly_mul_int_z(a: list[int], b: list[int], n: int) -> list[int]:
    """Multiply two polynomials over Z[x]/(x^n+1) exactly using Python big ints."""
    c = [0] * n
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            idx = i + j
            val = ai * bj
            if idx < n:
                c[idx] += val
            else:
                c[idx - n] -= val
    return c


def _poly_mul_int_z_scalar(k: list[int], a: list[int], n: int) -> list[int]:
    """Multiply polynomial k by polynomial a over Z[x]/(x^n+1)."""
    return _poly_mul_int_z(k, a, n)


def _field_norm(f: list[int], n: int) -> list[int]:
    """Compute field norm N(f) from Z[x]/(x^n+1) to Z[x]/(x^{n/2}+1).

    N(f)(y) = f_0(y)^2 - y * f_1(y)^2
    where f(x) = f_0(x^2) + x*f_1(x^2).
    """
    h = n // 2
    f0 = [f[2 * i] for i in range(h)]
    f1 = [f[2 * i + 1] for i in range(h)]
    f0sq = _poly_mul_int_z(f0, f0, h)
    f1sq = _poly_mul_int_z(f1, f1, h)

    # N(f)[0] = f0sq[0] + f1sq[h-1]  (wrapping: y*f1sq gives -f1sq[h-1] at index 0)
    # N(f)[i] = f0sq[i] - f1sq[i-1]  for i >= 1
    result = [0] * h
    result[0] = f0sq[0] + f1sq[h - 1]
    for i in range(1, h):
        result[i] = f0sq[i] - f1sq[i - 1]
    return result


def _tower_conjugate(f: list[int]) -> list[int]:
    """Compute tower conjugate: f*(x) = f_0(x^2) - x*f_1(x^2).

    Negates the odd-indexed coefficients.
    """
    result = list(f)
    for i in range(1, len(f), 2):
        result[i] = -result[i]
    return result


def _lift(fp: list[int], gp: list[int], f: list[int], g: list[int], n: int) -> tuple:
    """Lift (F', G') from degree n/2 to degree n.

    F = g*(x) * F'(x^2) in Z[x]/(x^n+1)
    G = f*(x) * G'(x^2) in Z[x]/(x^n+1)
    where f*(x) and g*(x) are tower conjugates.
    """
    h = n // 2
    # Embed F' and G' into degree n by replacing x with x^2
    fp_lift = [0] * n
    gp_lift = [0] * n
    for i in range(h):
        fp_lift[2 * i] = fp[i]
        gp_lift[2 * i] = gp[i]

    f_conj = _tower_conjugate(f)
    g_conj = _tower_conjugate(g)

    # F = g_conj * F'(x^2), G = f_conj * G'(x^2)
    F = _poly_mul_int_z(g_conj, fp_lift, n)
    G = _poly_mul_int_z(f_conj, gp_lift, n)
    return F, G


def _babai_reduce_fft(F: list[int], G: list[int], f: list[int], g: list[int], n: int) -> list[int]:
    """Compute Babai rounding k using complex FFT.

    k = round(Re(IFFT((F*conj(f) + G*conj(g)) / (|f|^2 + |g|^2))))
    in the FFT domain.

    Works when coefficients fit in float64 (< 53 bits).
    """
    import cmath
    from .fft import fft as _fft, ifft as _ifft

    fC = _fft([complex(v) for v in f], n)
    gC = _fft([complex(v) for v in g], n)
    FC = _fft([complex(v) for v in F], n)
    GC = _fft([complex(v) for v in G], n)

    kC = [0j] * n
    for i in range(n):
        fi, gi = fC[i], gC[i]
        Fi, Gi = FC[i], GC[i]
        fi_conj = fi.conjugate()
        gi_conj = gi.conjugate()
        num = Fi * fi_conj + Gi * gi_conj
        denom = fi * fi_conj + gi * gi_conj
        if denom.real != 0 or denom.imag != 0:
            kC[i] = num / denom

    k_ifft = _ifft(kC, n)
    return [round(v.real) for v in k_ifft]


def _babai_reduce_bigfloat(F: list[int], G: list[int], f: list[int], g: list[int], n: int) -> list[int]:
    """Compute Babai rounding k using Python's mpmath for high-precision arithmetic.

    Required when coefficient bit lengths exceed float64 precision (53 bits).
    """
    try:
        import mpmath
    except ImportError:
        # Fall back to float64 FFT (may lose precision for large coefficients)
        return _babai_reduce_fft(F, G, f, g, n)

    from .fft import _fft_log_n as _fft_logn_fn, _fft_bit_rev

    # Determine required precision based on coefficient bit lengths
    max_bits = max(
        max((v.bit_length() for v in f), default=0),
        max((v.bit_length() for v in g), default=0),
        max((abs(v).bit_length() for v in F), default=0),
        max((abs(v).bit_length() for v in G), default=0),
    )
    prec = max_bits * 2 + _fft_logn_fn(n) * 64 + 256
    mp = mpmath.mp
    old_prec = mp.prec
    mp.prec = prec

    try:
        def to_mpc(lst):
            return [mpmath.mpc(int(v), 0) for v in lst]

        def do_fft(arr):
            """In-place forward FFT using mpmath."""
            logn = _fft_logn_fn(n)
            k = 0
            length = n >> 1
            while length >= 1:
                start = 0
                while start < n:
                    k += 1
                    brk = _fft_bit_rev(k, logn)
                    angle = mpmath.pi * brk / n
                    w = mpmath.mpc(mpmath.cos(angle), mpmath.sin(angle))
                    for j in range(start, start + length):
                        t = w * arr[j + length]
                        arr[j + length] = arr[j] - t
                        arr[j] = arr[j] + t
                    start += 2 * length
                length >>= 1

        def do_ifft(arr):
            """In-place inverse FFT using mpmath."""
            logn = _fft_logn_fn(n)
            k = n
            length = 1
            while length < n:
                start = n - 2 * length
                while start >= 0:
                    k -= 1
                    brk = _fft_bit_rev(k, logn)
                    angle = mpmath.pi * brk / n
                    w_inv = mpmath.mpc(mpmath.cos(angle), -mpmath.sin(angle))
                    for j in range(start, start + length):
                        t = arr[j]
                        arr[j] = t + arr[j + length]
                        arr[j + length] = w_inv * (t - arr[j + length])
                    start -= 2 * length
                length <<= 1
            inv_n = mpmath.mpf(1) / n
            for i in range(n):
                arr[i] = arr[i] * inv_n

        fA = to_mpc(f)
        gA = to_mpc(g)
        FA = to_mpc(F)
        GA = to_mpc(G)

        do_fft(fA)
        do_fft(gA)
        do_fft(FA)
        do_fft(GA)

        kA = [mpmath.mpc(0) for _ in range(n)]
        for i in range(n):
            fi_conj = mpmath.mpc(fA[i].real, -fA[i].imag)
            gi_conj = mpmath.mpc(gA[i].real, -gA[i].imag)
            num = FA[i] * fi_conj + GA[i] * gi_conj
            denom_re = fA[i].real**2 + fA[i].imag**2 + gA[i].real**2 + gA[i].imag**2
            if denom_re != 0:
                kA[i] = mpmath.mpc(num.real / denom_re, num.imag / denom_re)

        do_ifft(kA)

        result = [int(mpmath.nint(v.real)) for v in kA]
        return result
    finally:
        mp.prec = old_prec


def _fft_log_n(n: int) -> int:
    logn = 0
    t = n
    while t > 1:
        t >>= 1
        logn += 1
    return logn


def _max_bits(polys: list[list[int]]) -> int:
    """Return the maximum bit length of coefficients across all polynomials."""
    result = 0
    for p in polys:
        for v in p:
            b = abs(v).bit_length()
            if b > result:
                result = b
    return result


def _ntru_solve_recursive(n: int, f: list[int], g: list[int]) -> tuple:
    """Recursively solve f*G - g*F = Q over Z[x]/(x^n+1).

    Returns (F, G) as lists of Python ints.
    Raises ValueError if no solution exists.
    """
    if n == 1:
        # Base case: solve f[0]*G[0] - g[0]*F[0] = Q over Z using extended GCD.
        fv = f[0]
        gv = g[0]

        # Extended GCD: gcd, u, v such that fv*u + gv*v = gcd
        def ext_gcd(a, b):
            if b == 0:
                return a, 1, 0
            g2, u, v = ext_gcd(b, a % b)
            return g2, v, u - (a // b) * v

        gcd_val, u, v = ext_gcd(fv, gv)
        if Q % gcd_val != 0:
            raise ValueError("gcd does not divide Q at base case")

        scale = Q // gcd_val
        # f*G - g*F = Q: G = u*scale, F = -v*scale
        G_val = u * scale
        F_val = -v * scale
        return [F_val], [G_val]

    # Compute field norms
    f_norm = _field_norm(f, n)
    g_norm = _field_norm(g, n)

    # Recursively solve for half-degree problem
    Fp, Gp = _ntru_solve_recursive(n // 2, f_norm, g_norm)

    # Lift from n/2 to n
    F, G = _lift(Fp, Gp, f, g, n)

    # Babai reduction: run 2 rounds
    for _ in range(2):
        max_b = _max_bits([f, g, F, G])
        if max_b <= 53:
            k = _babai_reduce_fft(F, G, f, g, n)
        else:
            k = _babai_reduce_bigfloat(F, G, f, g, n)

        kf = _poly_mul_int_z(k, f, n)
        kg = _poly_mul_int_z(k, g, n)
        for i in range(n):
            F[i] -= kf[i]
            G[i] -= kg[i]

    return F, G


def _verify_ntru(f: list[int], g: list[int], F: list[int], G: list[int], n: int) -> bool:
    """Verify f*G - g*F = Q exactly over Z[x]/(x^n+1)."""
    fG = _poly_mul_int_z(f, G, n)
    gF = _poly_mul_int_z(g, F, n)
    if fG[0] - gF[0] != Q:
        return False
    for i in range(1, n):
        if fG[i] - gF[i] != 0:
            return False
    return True


def ntru_keygen(params: Params, rng=None):
    """Generate NTRU key pair (f, g, F) for FN-DSA.

    Returns (f, g, F) where f*G - g*F = Q mod (x^n+1).
    G is not returned (it can be recovered via the NTRU equation during signing).

    rng: callable(n_bytes) -> bytes
    """
    import os
    if rng is None:
        rng = os.urandom

    n = params.n
    sigma = _ntru_sigma(n)

    for attempt in range(1000):
        # Sample f and g from D_{Z, sigma}
        f = [sample_gaussian(sigma, rng) for _ in range(n)]
        g = [sample_gaussian(sigma, rng) for _ in range(n)]

        # f must be invertible mod 2: XOR of all coefficients must be 1
        xor_sum = 0
        for v in f:
            xor_sum ^= v & 1
        if xor_sum == 0:
            continue

        # f must be invertible mod q: all NTT coefficients must be nonzero
        f_mod_q = [((v % Q) + Q) % Q for v in f]
        f_ntt = _ntt(f_mod_q, n)
        if any(v == 0 for v in f_ntt):
            continue

        # Gram-Schmidt norm bound: ||f||^2 + ||g||^2 <= 1.17^2 * Q * n
        norm_sq = sum(v * v for v in f) + sum(v * v for v in g)
        if norm_sq > 1.17 * 1.17 * Q * n:
            continue

        # Solve the NTRU equation
        try:
            F, G = _ntru_solve_recursive(n, f, g)
        except (ValueError, RecursionError):
            continue

        # Convert to int (should already be Python ints)
        F = [int(v) for v in F]
        G = [int(v) for v in G]

        # Check coefficients fit in int8 range for F (8-bit encoding)
        if any(v < -128 or v > 127 for v in F):
            continue

        # Verify the NTRU equation holds exactly
        if not _verify_ntru(f, g, F, G, n):
            continue

        return f, g, F

    raise RuntimeError("NTRU key generation failed after 1000 attempts")
