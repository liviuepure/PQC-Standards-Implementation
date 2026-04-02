"""NTT mod q=12289 for FN-DSA (FIPS 206).

Negacyclic NTT over Z_q[x]/(x^n+1) with q=12289, primitive root g=11.
Twiddle factor: psi_n = 11^((q-1)/(2n)) mod q — a primitive 2n-th root of unity.
Butterfly ordering: bit-reversed twiddle indices (Cooley-Tukey), matching Go reference.
"""

Q = 12289


def _pow_mod(base: int, exp: int, mod: int) -> int:
    return pow(base, exp, mod)


def _bit_rev(x: int, bits: int) -> int:
    result = 0
    for _ in range(bits):
        result = (result << 1) | (x & 1)
        x >>= 1
    return result


def _build_zetas(n: int) -> list[int]:
    """Build forward NTT twiddle factors (bit-reversed powers of psi_n)."""
    log_n = n.bit_length() - 1
    psi = _pow_mod(11, (Q - 1) // (2 * n), Q)
    zetas = [0] * (n + 1)
    # k starts from 1, same as Go: k=0 is unused
    # For each butterfly group k (1-indexed), zeta = psi^bit_rev(k, log_n)
    for k in range(1, n + 1):
        zetas[k] = _pow_mod(psi, _bit_rev(k, log_n), Q)
    return zetas


def _build_zetas_inv(n: int) -> list[int]:
    """Build inverse NTT twiddle factors."""
    log_n = n.bit_length() - 1
    psi = _pow_mod(11, (Q - 1) // (2 * n), Q)
    psi_inv = _pow_mod(psi, Q - 2, Q)
    zetas_inv = [0] * (n + 1)
    for k in range(1, n + 1):
        zetas_inv[k] = _pow_mod(psi_inv, _bit_rev(k, log_n), Q)
    return zetas_inv


# Precomputed tables for n=512 and n=1024
_ZETAS_512 = None
_ZETAS_1024 = None
_ZETAS_INV_512 = None
_ZETAS_INV_1024 = None


def _get_zetas(n: int) -> list[int]:
    global _ZETAS_512, _ZETAS_1024
    if n == 512:
        if _ZETAS_512 is None:
            _ZETAS_512 = _build_zetas(512)
        return _ZETAS_512
    else:
        if _ZETAS_1024 is None:
            _ZETAS_1024 = _build_zetas(1024)
        return _ZETAS_1024


def _get_zetas_inv(n: int) -> list[int]:
    global _ZETAS_INV_512, _ZETAS_INV_1024
    if n == 512:
        if _ZETAS_INV_512 is None:
            _ZETAS_INV_512 = _build_zetas_inv(512)
        return _ZETAS_INV_512
    else:
        if _ZETAS_INV_1024 is None:
            _ZETAS_INV_1024 = _build_zetas_inv(1024)
        return _ZETAS_INV_1024


def ntt(a: list[int], n: int) -> list[int]:
    """In-place forward negacyclic NTT over Z_q[x]/(x^n+1).

    Mirrors Go NTT: iterates length from n/2 down to 1 (outer),
    uses bit-reversed twiddle indices k=1..n.
    Output is in bit-reversed order.
    """
    zetas = _get_zetas(n)
    a = list(a)
    k = 0
    length = n >> 1
    while length >= 1:
        start = 0
        while start < n:
            k += 1
            zeta = zetas[k]
            for j in range(start, start + length):
                t = zeta * a[j + length] % Q
                a[j + length] = (a[j] - t) % Q
                a[j] = (a[j] + t) % Q
            start += 2 * length
        length >>= 1
    return a


def intt(a: list[int], n: int) -> list[int]:
    """In-place inverse negacyclic NTT over Z_q[x]/(x^n+1).

    Mirrors Go INTT: iterates length from 1 up to n/2,
    processes blocks in reverse order, uses inverse twiddle factors,
    then scales by n^{-1} mod Q.
    """
    zetas_inv = _get_zetas_inv(n)
    a = list(a)
    k = n
    length = 1
    while length < n:
        # Process starts in reverse order (matching Go: start from n-2*length down to 0)
        start = n - 2 * length
        while start >= 0:
            k -= 1
            zeta_inv = zetas_inv[k]
            for j in range(start, start + length):
                t = a[j]
                a[j] = (t + a[j + length]) % Q
                a[j + length] = zeta_inv * ((t - a[j + length]) % Q) % Q
            start -= 2 * length
        length <<= 1
    # Scale by n^{-1} mod Q
    n_inv = _pow_mod(n, Q - 2, Q)
    return [x * n_inv % Q for x in a]


def poly_mul_ntt(a: list[int], b: list[int], n: int) -> list[int]:
    """Multiply two polynomials mod (x^n+1, Q) via NTT.

    Inputs should be in [0, Q).
    """
    fa = ntt(a, n)
    fb = ntt(b, n)
    fc = [fa[i] * fb[i] % Q for i in range(n)]
    return intt(fc, n)


def poly_inv_ntt(f: list[int], n: int) -> list[int]:
    """Compute modular inverse of f in Z_q[x]/(x^n+1) via NTT.

    Uses Fermat's little theorem: a^{-1} = a^{q-2} mod q for each NTT coefficient.
    """
    ff = ntt(f, n)
    ff_inv = [_pow_mod(x, Q - 2, Q) for x in ff]
    return intt(ff_inv, n)
