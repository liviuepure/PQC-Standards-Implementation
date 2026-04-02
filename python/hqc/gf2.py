"""GF(2) polynomial arithmetic using Python arbitrary-precision integers.

Each polynomial is represented as a Python int where bit i is the coefficient
of x^i. This gives us XOR for addition, bit manipulation for coefficients,
and arbitrary precision for free.
"""


def gf2_add(a: int, b: int) -> int:
    """Add two GF(2) polynomials (XOR)."""
    return a ^ b


def gf2_get_bit(a: int, i: int) -> int:
    """Get the coefficient of x^i in polynomial a."""
    return (a >> i) & 1


def gf2_set_bit(a: int, i: int) -> int:
    """Return a with the coefficient of x^i set to 1."""
    return a | (1 << i)


def gf2_clear_bit(a: int, i: int) -> int:
    """Return a with the coefficient of x^i set to 0."""
    return a & ~(1 << i)


def gf2_weight(a: int) -> int:
    """Compute the Hamming weight (number of 1 bits) of a GF(2) polynomial."""
    return bin(a).count('1')


def gf2_mul_mod(a: int, b: int, n: int) -> int:
    """Multiply two GF(2) polynomials modulo (x^n - 1).

    This computes a * b in GF(2)[x] / (x^n - 1).
    Uses schoolbook multiplication with reduction.
    """
    result = 0
    # Iterate over set bits of b
    bb = b
    shift = 0
    while bb:
        if bb & 1:
            result ^= (a << shift)
        bb >>= 1
        shift += 1

    # Reduce modulo x^n - 1 (i.e., x^n = 1, so x^(n+k) = x^k)
    result = _reduce_mod_xn_minus_1(result, n)
    return result


def _reduce_mod_xn_minus_1(a: int, n: int) -> int:
    """Reduce polynomial a modulo (x^n - 1).

    Since x^n = 1 in the quotient ring, any term x^(n+k) wraps to x^k.
    """
    mask = (1 << n) - 1
    result = a & mask
    a >>= n
    while a:
        result ^= (a & mask)
        a >>= n
    return result


def gf2_sparse_mul_mod(a: int, positions: list, n: int) -> int:
    """Multiply GF(2) polynomial a by a sparse polynomial given by its support positions.

    The sparse polynomial b = sum(x^pos for pos in positions).
    Result is computed mod (x^n - 1).
    """
    result = 0
    for pos in positions:
        result ^= _rotate_left(a, pos, n)
    return result


def _rotate_left(a: int, shift: int, n: int) -> int:
    """Rotate polynomial a left by shift positions modulo x^n - 1."""
    if shift == 0:
        return a
    shift = shift % n
    mask = (1 << n) - 1
    return ((a << shift) | (a >> (n - shift))) & mask


def gf2_to_bytes(a: int, n: int) -> bytes:
    """Serialize a GF(2) polynomial of degree < n to bytes (little-endian bit order).

    The number of bytes is ceil(n / 8).
    """
    num_bytes = (n + 7) // 8
    result = bytearray(num_bytes)
    for i in range(num_bytes):
        result[i] = (a >> (i * 8)) & 0xFF
    return bytes(result)


def gf2_from_bytes(data: bytes, n: int) -> int:
    """Deserialize a GF(2) polynomial from bytes (little-endian bit order).

    Only the first n bits are used.
    """
    result = int.from_bytes(data, byteorder='little')
    mask = (1 << n) - 1
    return result & mask


def gf2_random_fixed_weight(rand_bytes: bytes, n: int, w: int) -> int:
    """Generate a random GF(2) polynomial of length n with exactly w nonzero coefficients.

    Uses Fisher-Yates-like rejection sampling from random bytes.
    The rand_bytes should contain enough randomness (at least 4*w bytes recommended).
    """
    # Parse random bytes into 32-bit values for position sampling
    positions = set()
    offset = 0
    while len(positions) < w:
        if offset + 4 > len(rand_bytes):
            raise ValueError("Not enough random bytes for weight generation")
        val = int.from_bytes(rand_bytes[offset:offset+4], byteorder='little')
        offset += 4
        pos = val % n
        positions.add(pos)

    result = 0
    for pos in positions:
        result = gf2_set_bit(result, pos)
    return result


def gf2_random_fixed_weight_from_shake(shake, n: int, w: int) -> int:
    """Generate a random GF(2) polynomial of length n with exactly w nonzero coefficients.

    Uses a SHAKE-256 instance for randomness via rejection sampling.
    """
    positions = []
    seen = set()
    # We need to sample w distinct positions from [0, n)
    # Use 4-byte chunks from SHAKE for each candidate
    while len(positions) < w:
        rand_bytes = shake.digest(4 + len(positions) * 0)
        # Actually we need to squeeze incrementally. Use a counter approach.
        break

    # Better approach: squeeze enough bytes at once and parse
    # For rejection sampling, we need roughly w * 4 bytes, but may need more
    # Squeeze a generous amount
    needed = w * 8  # generous estimate
    data = shake.digest(needed)

    positions = []
    seen = set()
    offset = 0
    while len(positions) < w:
        if offset + 4 > len(data):
            # Need more randomness - squeeze more
            needed *= 2
            data = shake.digest(needed)
        val = int.from_bytes(data[offset:offset+4], byteorder='little')
        offset += 4
        pos = val % n
        if pos not in seen:
            seen.add(pos)
            positions.append(pos)

    result = 0
    for pos in positions:
        result = gf2_set_bit(result, pos)
    return result
