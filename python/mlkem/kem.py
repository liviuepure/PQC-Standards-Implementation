"""ML-KEM (Key Encapsulation Mechanism) per FIPS 203.

Implements Algorithms 16, 17, 18.
"""

import os
import hmac

from mlkem.field import Q
from mlkem.params import MLKEMParams
from mlkem.encode import byte_decode
from mlkem.hash_funcs import G, H, J
from mlkem.kpke import kpke_keygen, kpke_encrypt, kpke_decrypt


def keygen(params: MLKEMParams) -> tuple[bytes, bytes]:
    """Algorithm 16: ML-KEM Key Generation.

    Output: (encapsulation key ek, decapsulation key dk).
    """
    d = os.urandom(32)
    z = os.urandom(32)

    ek_pke, dk_pke = kpke_keygen(d, params)

    ek = ek_pke
    dk = dk_pke + ek + H(ek) + z

    return ek, dk


def encaps(ek: bytes, params: MLKEMParams) -> tuple[bytes, bytes]:
    """Algorithm 17: ML-KEM Encapsulation.

    Input: encapsulation key ek.
    Output: (shared secret K, ciphertext c).
    """
    # Validate ek: check all ByteDecode_12 coefficients are < Q
    k = params.k
    for i in range(k):
        coeffs = byte_decode(12, ek[384 * i: 384 * (i + 1)])
        for coeff in coeffs:
            if coeff >= Q:
                raise ValueError(
                    f"Invalid encapsulation key: coefficient {coeff} >= Q"
                )

    m = os.urandom(32)
    K_bar, r = G(m + H(ek))
    c = kpke_encrypt(ek, m, r, params)
    return K_bar, c


def decaps(dk: bytes, c: bytes, params: MLKEMParams) -> bytes:
    """Algorithm 18: ML-KEM Decapsulation.

    Input: decapsulation key dk, ciphertext c.
    Output: shared secret K.
    """
    k = params.k

    # Parse dk
    dk_pke = dk[:384 * k]
    ek = dk[384 * k: 768 * k + 32]
    h_ek = dk[768 * k + 32: 768 * k + 64]
    z = dk[768 * k + 64: 768 * k + 96]

    # Decrypt
    m_prime = kpke_decrypt(dk_pke, c, params)

    # Re-derive
    K_bar_prime, r_prime = G(m_prime + h_ek)

    # Re-encrypt
    c_prime = kpke_encrypt(ek, m_prime, r_prime, params)

    # Implicit rejection key
    K_reject = J(z + c)

    # Constant-time comparison
    if hmac.compare_digest(c, c_prime):
        return K_bar_prime
    else:
        return K_reject
