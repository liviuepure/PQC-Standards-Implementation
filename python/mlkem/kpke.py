"""K-PKE (internal PKE scheme) per FIPS 203.

Implements Algorithms 13, 14, 15.
"""

from mlkem.field import Q
from mlkem.params import MLKEMParams
from mlkem.ntt import ntt, ntt_inverse, multiply_ntts
from mlkem.encode import byte_encode, byte_decode
from mlkem.compress import compress_poly, decompress_poly
from mlkem.hash_funcs import G, xof, prf
from mlkem.sampling import sample_ntt, sample_poly_cbd


def _add_polys(a: list[int], b: list[int]) -> list[int]:
    """Add two polynomials coefficient-wise mod Q."""
    return [(a[i] + b[i]) % Q for i in range(256)]


def _sub_polys(a: list[int], b: list[int]) -> list[int]:
    """Subtract two polynomials coefficient-wise mod Q."""
    return [(a[i] - b[i]) % Q for i in range(256)]


def kpke_keygen(d: bytes, params: MLKEMParams) -> tuple[bytes, bytes]:
    """Algorithm 13: K-PKE Key Generation.

    Input: 32-byte seed d.
    Output: (encryption key ek_pke, decryption key dk_pke).
    """
    k = params.k
    eta1 = params.eta1

    rho, sigma = G(d + bytes([k]))

    # Generate matrix A_hat in NTT domain (k x k)
    A_hat = []
    for i in range(k):
        row = []
        for j in range(k):
            xof_bytes = xof(rho, i, j)
            row.append(sample_ntt(xof_bytes))
        A_hat.append(row)

    # Generate secret vector s
    N = 0
    s = []
    for i in range(k):
        prf_bytes = prf(sigma, N, 64 * eta1)
        s.append(ntt(sample_poly_cbd(prf_bytes, eta1)))
        N += 1

    # Generate error vector e
    e = []
    for i in range(k):
        prf_bytes = prf(sigma, N, 64 * eta1)
        e.append(ntt(sample_poly_cbd(prf_bytes, eta1)))
        N += 1

    # t_hat = A_hat * s + e (in NTT domain)
    t_hat = []
    for i in range(k):
        acc = [0] * 256
        for j in range(k):
            prod = multiply_ntts(A_hat[i][j], s[j])
            acc = _add_polys(acc, prod)
        t_hat.append(_add_polys(acc, e[i]))

    # Encode ek_pke = ByteEncode_12(t_hat[0]) || ... || ByteEncode_12(t_hat[k-1]) || rho
    ek_pke = b""
    for i in range(k):
        ek_pke += byte_encode(12, t_hat[i])
    ek_pke += rho

    # Encode dk_pke = ByteEncode_12(s[0]) || ... || ByteEncode_12(s[k-1])
    dk_pke = b""
    for i in range(k):
        dk_pke += byte_encode(12, s[i])

    return ek_pke, dk_pke


def kpke_encrypt(ek_pke: bytes, m: bytes, r: bytes, params: MLKEMParams) -> bytes:
    """Algorithm 14: K-PKE Encryption.

    Input: encryption key ek_pke, 32-byte message m, 32-byte randomness r.
    Output: ciphertext c.
    """
    k = params.k
    eta1 = params.eta1
    eta2 = params.eta2
    du = params.du
    dv = params.dv

    # Decode t_hat from ek_pke
    t_hat = []
    for i in range(k):
        decoded = byte_decode(12, ek_pke[384 * i: 384 * (i + 1)])
        t_hat.append([c % Q for c in decoded])
    rho = ek_pke[384 * k: 384 * k + 32]

    # Regenerate matrix A_hat
    A_hat = []
    for i in range(k):
        row = []
        for j in range(k):
            xof_bytes = xof(rho, i, j)
            row.append(sample_ntt(xof_bytes))
        A_hat.append(row)

    # Generate random vectors
    N = 0
    r_vec = []
    for i in range(k):
        prf_bytes = prf(r, N, 64 * eta1)
        r_vec.append(ntt(sample_poly_cbd(prf_bytes, eta1)))
        N += 1

    e1 = []
    for i in range(k):
        prf_bytes = prf(r, N, 64 * eta2)
        e1.append(sample_poly_cbd(prf_bytes, eta2))
        N += 1

    prf_bytes = prf(r, N, 64 * eta2)
    e2 = sample_poly_cbd(prf_bytes, eta2)

    # u = NTT^{-1}(A_hat^T * r_vec) + e1
    u = []
    for i in range(k):
        acc = [0] * 256
        for j in range(k):
            # A_hat^T[i][j] = A_hat[j][i]
            prod = multiply_ntts(A_hat[j][i], r_vec[j])
            acc = _add_polys(acc, prod)
        u_i = ntt_inverse(acc)
        u.append(_add_polys(u_i, e1[i]))

    # v = NTT^{-1}(t_hat^T * r_vec) + e2 + Decompress_1(ByteDecode_1(m))
    v_acc = [0] * 256
    for i in range(k):
        prod = multiply_ntts(t_hat[i], r_vec[i])
        v_acc = _add_polys(v_acc, prod)
    v = ntt_inverse(v_acc)
    v = _add_polys(v, e2)

    # Decode and decompress message
    m_poly = byte_decode(1, m)
    m_decomp = decompress_poly(1, m_poly)
    v = _add_polys(v, m_decomp)

    # Compress and encode ciphertext
    c1 = b""
    for i in range(k):
        c1 += byte_encode(du, compress_poly(du, u[i]))
    c2 = byte_encode(dv, compress_poly(dv, v))

    return c1 + c2


def kpke_decrypt(dk_pke: bytes, c: bytes, params: MLKEMParams) -> bytes:
    """Algorithm 15: K-PKE Decryption.

    Input: decryption key dk_pke, ciphertext c.
    Output: 32-byte message m.
    """
    k = params.k
    du = params.du
    dv = params.dv

    # Decode and decompress u from ciphertext
    u = []
    for i in range(k):
        start = 32 * du * i
        end = 32 * du * (i + 1)
        u_compressed = byte_decode(du, c[start:end])
        u.append(decompress_poly(du, u_compressed))

    # Decode and decompress v from ciphertext
    c2_start = 32 * du * k
    v_compressed = byte_decode(dv, c[c2_start:])
    v = decompress_poly(dv, v_compressed)

    # Decode secret key
    s_hat = []
    for i in range(k):
        decoded = byte_decode(12, dk_pke[384 * i: 384 * (i + 1)])
        s_hat.append([c_val % Q for c_val in decoded])

    # w = v - NTT^{-1}(s_hat^T * NTT(u))
    w = list(v)
    for i in range(k):
        u_hat_i = ntt(u[i])
        prod = multiply_ntts(s_hat[i], u_hat_i)
        prod_inv = ntt_inverse(prod)
        w = _sub_polys(w, prod_inv)

    # Compress and encode message
    m = byte_encode(1, compress_poly(1, w))
    return m
