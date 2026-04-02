"""Tensor product code: RS (outer) x RM (inner).

The tensor code encodes k bytes into n1*n2 bits:
1. RS encode: k bytes -> n1 GF(256) symbols
2. RM encode each symbol: n1 symbols -> n1 * n2 bits

Decoding reverses the process:
1. RM decode each block of n2 bits -> n1 GF(256) symbols
2. RS decode: n1 symbols -> k bytes
"""

from hqc.params import HQCParams
from hqc.rm import rm_encode, rm_decode
from hqc.rs import rs_encode, rs_decode


def tensor_encode(msg: bytes, params: HQCParams) -> int:
    """Encode k bytes into an n1*n2-bit integer using the tensor product code.

    msg: k bytes to encode
    Returns: integer with n1*n2 bits
    """
    k = params.k
    n1 = params.n1
    n2 = params.n2
    multiplicity = params.multiplicity

    assert len(msg) == k

    # Step 1: RS encode
    msg_list = list(msg)
    rs_codeword = rs_encode(msg_list, params)  # n1 GF(256) symbols

    # Step 2: RM encode each symbol
    result = 0
    for i in range(n1):
        rm_codeword = rm_encode(rs_codeword[i], multiplicity)
        result |= (rm_codeword << (i * n2))

    return result


def tensor_decode(received: int, params: HQCParams) -> tuple:
    """Decode an n1*n2-bit integer to recover k bytes.

    received: integer with n1*n2 bits
    Returns: (decoded_bytes, success)
    """
    n1 = params.n1
    n2 = params.n2
    k = params.k
    multiplicity = params.multiplicity
    n2_mask = (1 << n2) - 1

    # Step 1: RM decode each block of n2 bits
    rs_received = []
    for i in range(n1):
        block = (received >> (i * n2)) & n2_mask
        symbol = rm_decode(block, n2, multiplicity)
        rs_received.append(symbol)

    # Step 2: RS decode
    decoded, success = rs_decode(rs_received, params)
    if not success:
        return bytes(decoded[:k]), False

    return bytes(decoded[:k]), True
