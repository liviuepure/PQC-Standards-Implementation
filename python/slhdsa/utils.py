"""Utility functions for SLH-DSA per FIPS 205."""


def to_int(x: bytes, byteorder: str = "big") -> int:
    """Convert bytes to integer (Algorithm 1)."""
    return int.from_bytes(x, byteorder)


def to_byte(x: int, n: int) -> bytes:
    """Convert integer to n-byte string (Algorithm 2)."""
    return x.to_bytes(n, "big")


def base_2b(x: bytes, b: int, out_len: int) -> list:
    """Compute base-2^b representation of x (Algorithm 3).

    Args:
        x: Input byte string.
        b: Number of bits per output element.
        out_len: Number of output elements.

    Returns:
        List of out_len integers, each in range [0, 2^b - 1].
    """
    total = int.from_bytes(x, "big")
    baseb = []
    # Process bits from MSB to LSB
    bits = 8 * len(x)
    mask = (1 << b) - 1
    for i in range(out_len):
        # Extract b bits starting from position (bits - b*(i+1))
        shift = bits - b * (i + 1)
        if shift >= 0:
            baseb.append((total >> shift) & mask)
        else:
            baseb.append((total << (-shift)) & mask)
    return baseb
