"""Number Theoretic Transform (NTT) operations per FIPS 203.

Implements Algorithms 9-12.
"""

from mlkem.field import Q, mod_q, field_mul, field_sub, field_add


def bit_rev7(n: int) -> int:
    """Reverse the 7 least significant bits of n."""
    result = 0
    for _ in range(7):
        result = (result << 1) | (n & 1)
        n >>= 1
    return result


def _precompute_zetas() -> list[int]:
    """Precompute zeta values: zetas[i] = 17^(bitrev7(i)) mod Q."""
    zetas = []
    for i in range(128):
        zetas.append(pow(17, bit_rev7(i), Q))
    return zetas


ZETAS: list[int] = _precompute_zetas()


def ntt(f: list[int]) -> list[int]:
    """Algorithm 9: Number-Theoretic Transform.

    Input: polynomial f with 256 coefficients in Z_Q.
    Output: NTT representation f_hat.
    """
    f_hat = list(f)
    k = 1
    length = 128
    while length >= 2:
        start = 0
        while start < 256:
            zeta = ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = field_mul(zeta, f_hat[j + length])
                f_hat[j + length] = field_sub(f_hat[j], t)
                f_hat[j] = field_add(f_hat[j], t)
            start += 2 * length
        length //= 2
    return f_hat


def ntt_inverse(f_hat: list[int]) -> list[int]:
    """Algorithm 10: Inverse NTT.

    Input: NTT representation f_hat.
    Output: polynomial f with 256 coefficients in Z_Q.
    """
    f = list(f_hat)
    k = 127
    length = 2
    while length <= 128:
        start = 0
        while start < 256:
            zeta = ZETAS[k]
            k -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = field_add(t, f[j + length])
                f[j + length] = field_mul(zeta, field_sub(f[j + length], t))
            start += 2 * length
        length *= 2
    # Multiply all coefficients by 3303 = 128^{-1} mod Q
    inv128 = 3303
    f = [field_mul(c, inv128) for c in f]
    return f


def base_case_multiply(a0: int, a1: int, b0: int, b1: int, gamma: int) -> tuple[int, int]:
    """Algorithm 12: Base case multiplication.

    Multiply two degree-1 polynomials modulo X^2 - gamma.
    """
    c0 = field_add(field_mul(a0, b0), field_mul(field_mul(a1, b1), gamma))
    c1 = field_add(field_mul(a0, b1), field_mul(a1, b0))
    return c0, c1


def multiply_ntts(f_hat: list[int], g_hat: list[int]) -> list[int]:
    """Algorithm 11: Multiplication in NTT domain.

    Pointwise multiplication of two NTT-domain polynomials.
    """
    h_hat = [0] * 256
    for i in range(64):
        gamma = ZETAS[64 + i]
        z0, z1 = base_case_multiply(
            f_hat[4 * i], f_hat[4 * i + 1],
            g_hat[4 * i], g_hat[4 * i + 1],
            gamma,
        )
        h_hat[4 * i] = z0
        h_hat[4 * i + 1] = z1

        z0, z1 = base_case_multiply(
            f_hat[4 * i + 2], f_hat[4 * i + 3],
            g_hat[4 * i + 2], g_hat[4 * i + 3],
            mod_q(Q - gamma),
        )
        h_hat[4 * i + 2] = z0
        h_hat[4 * i + 3] = z1
    return h_hat
