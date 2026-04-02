"""Complex FFT for FN-DSA (FIPS 206 / FALCON).

Negacyclic complex FFT over C[x]/(x^n+1), evaluating at the 2n-th primitive
roots of unity: omega_j = exp(i*pi*bit_rev(j)/n).

The butterfly structure uses bit-reversed twiddle indices k=1..n, matching
the Go reference implementation exactly.
"""
import math
import cmath


def _fft_log_n(n: int) -> int:
    logn = 0
    t = n
    while t > 1:
        t >>= 1
        logn += 1
    return logn


def _fft_bit_rev(k: int, logn: int) -> int:
    r = 0
    for _ in range(logn):
        r = (r << 1) | (k & 1)
        k >>= 1
    return r


def fft(f: list, n: int) -> list[complex]:
    """In-place forward negacyclic complex FFT over C[x]/(x^n+1).

    f: list of n real or complex values (polynomial coefficients).
    Returns list of n complex values (evaluation at bit-reversed 2n-th roots).

    Twiddle for group k: w_k = exp(i*pi*bit_rev(k, log2(n)) / n).
    Mirrors Go FFT exactly.
    """
    logn = _fft_log_n(n)
    a = [complex(v) for v in f]
    k = 0
    length = n >> 1
    while length >= 1:
        start = 0
        while start < n:
            k += 1
            brk = _fft_bit_rev(k, logn)
            w = cmath.exp(1j * math.pi * brk / n)
            for j in range(start, start + length):
                t = w * a[j + length]
                a[j + length] = a[j] - t
                a[j] = a[j] + t
            start += 2 * length
        length >>= 1
    return a


def ifft(f: list[complex], n: int) -> list[complex]:
    """In-place inverse negacyclic complex FFT over C[x]/(x^n+1).

    Inverse of fft(): ifft(fft(f)) = f (within floating-point precision).
    Result is scaled by 1/n.
    Mirrors Go IFFT exactly.
    """
    logn = _fft_log_n(n)
    a = list(f)
    k = n
    length = 1
    while length < n:
        # Process blocks in reverse order (matching Go: start from n-2*length down to 0)
        start = n - 2 * length
        while start >= 0:
            k -= 1
            brk = _fft_bit_rev(k, logn)
            w_inv = cmath.exp(-1j * math.pi * brk / n)
            for j in range(start, start + length):
                t = a[j]
                a[j] = t + a[j + length]
                a[j + length] = w_inv * (t - a[j + length])
            start -= 2 * length
        length <<= 1
    inv_n = 1.0 / n
    return [v * inv_n for v in a]


def split_fft(f: list[complex], n: int) -> tuple[list[complex], list[complex]]:
    """Split FFT-domain polynomial into two halves.

    Given f in FFT domain (bit-reversed), computes f0, f1 where
    f(x) = f0(x^2) + x*f1(x^2).

    Formula (FALCON spec §3.7.1):
      f0[k] = (f[2k] + f[2k+1]) / 2
      f1[k] = (f[2k] - f[2k+1]) / (2 * omega_j)
    where omega_j = exp(i*pi*(2j+1)/n) with j = bit_rev(k, log2(n)-1).
    Mirrors Go SplitFFT.
    """
    logn = _fft_log_n(n)
    h = n // 2
    f0 = [0j] * h
    f1 = [0j] * h
    for k in range(h):
        j = _fft_bit_rev(k, logn - 1)
        omega_j = cmath.exp(1j * math.pi * (2 * j + 1) / n)
        a = f[2 * k]
        b = f[2 * k + 1]
        f0[k] = (a + b) / 2
        f1[k] = (a - b) / (2 * omega_j)
    return f0, f1


def merge_fft(f0: list[complex], f1: list[complex], n: int) -> list[complex]:
    """Merge two FFT-domain half-polynomials into one.

    Inverse of split_fft. Given f0, f1, reconstructs f where
    f(x) = f0(x^2) + x*f1(x^2).

    Formula:
      f[2k]   = f0[k] + omega_j * f1[k]
      f[2k+1] = f0[k] - omega_j * f1[k]
    where omega_j = exp(i*pi*(2j+1)/n) with j = bit_rev(k, log2(n)-1).
    Mirrors Go MergeFFT.
    """
    logn = _fft_log_n(n)
    h = n // 2
    result = [0j] * n
    for k in range(h):
        j = _fft_bit_rev(k, logn - 1)
        omega_j = cmath.exp(1j * math.pi * (2 * j + 1) / n)
        t = omega_j * f1[k]
        result[2 * k] = f0[k] + t
        result[2 * k + 1] = f0[k] - t
    return result
