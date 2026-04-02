"""Reed-Muller RM(1,7) encode and decode.

RM(1,7) encodes 8 bits (1 byte) into 128 bits.
The generator matrix has rows corresponding to:
- Row 0: all-ones vector (length 128)
- Rows 1..7: the i-th bit of each position index

Decoding uses the Walsh-Hadamard transform to find the closest codeword.
With multiplicity, each byte is encoded into n2 = 128 * multiplicity bits.
"""


def rm_encode_single(msg_byte: int) -> int:
    """Encode a single byte using RM(1,7) into a 128-bit integer.

    msg_byte has 8 bits: b0 is the constant term, b1..b7 are the linear terms.
    The codeword c[j] for j in [0,128) is:
        c[j] = b0 XOR (b1 & j_0) XOR (b2 & j_1) XOR ... XOR (b7 & j_6)
    where j_i is bit i of j.
    """
    result = 0
    b0 = (msg_byte >> 0) & 1
    for j in range(128):
        bit = b0
        for i in range(7):
            if (msg_byte >> (i + 1)) & 1:
                bit ^= (j >> i) & 1
        if bit:
            result |= (1 << j)
    return result


def rm_encode(msg_byte: int, multiplicity: int) -> int:
    """Encode a byte using RM(1,7) with repetition (multiplicity).

    Returns n2 = 128 * multiplicity bits as an integer.
    The 128-bit codeword is repeated 'multiplicity' times.
    """
    codeword = rm_encode_single(msg_byte)
    result = 0
    for i in range(multiplicity):
        result |= (codeword << (128 * i))
    return result


def _walsh_hadamard_transform(v: list) -> list:
    """In-place Walsh-Hadamard transform on a list of length 128 (= 2^7).

    Transforms real-valued vector v such that v[i] = sum_j (-1)^(popcount(i&j)) * v[j].
    """
    n = len(v)
    h = 1
    while h < n:
        for i in range(0, n, h * 2):
            for j in range(i, i + h):
                x = v[j]
                y = v[j + h]
                v[j] = x + y
                v[j + h] = x - y
        h *= 2
    return v


def rm_decode(received: int, n2: int, multiplicity: int) -> int:
    """Decode a received n2-bit word to recover the original byte.

    Uses Walsh-Hadamard transform on the sum of all multiplicity copies.
    received is an integer with n2 bits.
    """
    # Sum the multiplicity copies (convert bits to +1/-1 and accumulate)
    sums = [0] * 128
    for m in range(multiplicity):
        block = (received >> (128 * m)) & ((1 << 128) - 1)
        for j in range(128):
            bit = (block >> j) & 1
            # Map 0 -> +1, 1 -> -1
            sums[j] += 1 - 2 * bit

    # Apply Walsh-Hadamard transform
    wht = _walsh_hadamard_transform(sums)

    # Find the index with maximum absolute value
    best_val = 0
    best_idx = 0
    for i in range(128):
        if abs(wht[i]) > abs(best_val):
            best_val = wht[i]
            best_idx = i

    # Recover the message byte
    # best_idx gives bits 1..7 of the message
    # The sign of best_val gives bit 0: positive means b0=0, negative means b0=1
    msg_byte = 0
    if best_val < 0:
        msg_byte = 1  # b0 = 1

    # Bits 1..7 come from the index
    for i in range(7):
        if (best_idx >> i) & 1:
            msg_byte |= (1 << (i + 1))

    return msg_byte
