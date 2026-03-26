"""Tests for core ML-KEM components."""

import unittest
import sys
import os

# Ensure the python directory is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mlkem.field import Q, mod_q, field_add, field_sub, field_mul, field_pow
from mlkem.ntt import ZETAS, ntt, ntt_inverse, multiply_ntts, bit_rev7
from mlkem.encode import byte_encode, byte_decode
from mlkem.compress import compress, decompress, compress_poly, decompress_poly
from mlkem.params import ML_KEM_512, ML_KEM_768, ML_KEM_1024


class TestField(unittest.TestCase):
    """Test finite field arithmetic."""

    def test_add(self):
        self.assertEqual(field_add(100, 200), 300)
        self.assertEqual(field_add(Q - 1, 1), 0)
        self.assertEqual(field_add(Q - 1, Q - 1), (2 * Q - 2) % Q)

    def test_sub(self):
        self.assertEqual(field_sub(200, 100), 100)
        self.assertEqual(field_sub(0, 1), Q - 1)
        self.assertEqual(field_sub(100, 100), 0)

    def test_mul(self):
        self.assertEqual(field_mul(0, 1234), 0)
        self.assertEqual(field_mul(1, 1234), 1234)
        self.assertEqual(field_mul(2, 2), 4)
        self.assertEqual(field_mul(Q - 1, Q - 1), ((Q - 1) * (Q - 1)) % Q)

    def test_pow(self):
        self.assertEqual(field_pow(17, 0), 1)
        self.assertEqual(field_pow(17, 1), 17)
        # 17 is a primitive root mod Q, so 17^(Q-1) = 1 (Fermat)
        self.assertEqual(field_pow(17, Q - 1), 1)

    def test_fermats_little_theorem(self):
        """For any a != 0, a^(Q-1) = 1 mod Q."""
        for a in [1, 2, 17, 100, 1000, Q - 1]:
            self.assertEqual(field_pow(a, Q - 1), 1, f"Failed for a={a}")

    def test_mod_q(self):
        self.assertEqual(mod_q(0), 0)
        self.assertEqual(mod_q(Q), 0)
        self.assertEqual(mod_q(-1), Q - 1)
        self.assertEqual(mod_q(Q + 5), 5)


class TestNTT(unittest.TestCase):
    """Test NTT operations."""

    def test_zetas_range(self):
        """All zetas should be in [0, Q)."""
        for z in ZETAS:
            self.assertGreaterEqual(z, 0)
            self.assertLess(z, Q)

    def test_zetas_first(self):
        """zetas[0] = 17^bitrev7(0) = 17^0 = 1."""
        self.assertEqual(ZETAS[0], 1)

    def test_ntt_roundtrip(self):
        """NTT followed by inverse NTT should return the original polynomial."""
        import random
        random.seed(42)
        f = [random.randint(0, Q - 1) for _ in range(256)]
        f_hat = ntt(f)
        f_recovered = ntt_inverse(f_hat)
        self.assertEqual(f, f_recovered)

    def test_ntt_roundtrip_zero(self):
        """NTT of zero polynomial should be zero."""
        f = [0] * 256
        f_hat = ntt(f)
        f_recovered = ntt_inverse(f_hat)
        self.assertEqual(f, f_recovered)

    def test_multiply_commutativity(self):
        """NTT multiplication should be commutative."""
        import random
        random.seed(123)
        f = [random.randint(0, Q - 1) for _ in range(256)]
        g = [random.randint(0, Q - 1) for _ in range(256)]
        f_hat = ntt(f)
        g_hat = ntt(g)
        fg = multiply_ntts(f_hat, g_hat)
        gf = multiply_ntts(g_hat, f_hat)
        self.assertEqual(fg, gf)


class TestEncode(unittest.TestCase):
    """Test byte encoding and decoding."""

    def test_roundtrip_d1(self):
        """Encode/decode round-trip for d=1."""
        import random
        random.seed(1)
        F = [random.randint(0, 1) for _ in range(256)]
        B = byte_encode(1, F)
        self.assertEqual(len(B), 32)
        F2 = byte_decode(1, B)
        self.assertEqual(F, F2)

    def test_roundtrip_d4(self):
        """Encode/decode round-trip for d=4."""
        import random
        random.seed(2)
        F = [random.randint(0, 15) for _ in range(256)]
        B = byte_encode(4, F)
        self.assertEqual(len(B), 128)
        F2 = byte_decode(4, B)
        self.assertEqual(F, F2)

    def test_roundtrip_d10(self):
        """Encode/decode round-trip for d=10."""
        import random
        random.seed(3)
        F = [random.randint(0, 1023) for _ in range(256)]
        B = byte_encode(10, F)
        self.assertEqual(len(B), 320)
        F2 = byte_decode(10, B)
        self.assertEqual(F, F2)

    def test_roundtrip_d12(self):
        """Encode/decode round-trip for d=12."""
        import random
        random.seed(4)
        F = [random.randint(0, Q - 1) for _ in range(256)]
        B = byte_encode(12, F)
        self.assertEqual(len(B), 384)
        F2 = byte_decode(12, B)
        self.assertEqual(F, F2)

    def test_encode_length(self):
        """Encoded output should be exactly 32*d bytes."""
        for d in [1, 4, 10, 12]:
            F = [0] * 256
            B = byte_encode(d, F)
            self.assertEqual(len(B), 32 * d, f"Wrong length for d={d}")


class TestCompress(unittest.TestCase):
    """Test compression and decompression."""

    def test_range_check(self):
        """Compressed values should be in [0, 2^d)."""
        for d in [1, 4, 10, 11]:
            for x in range(Q):
                c = compress(d, x)
                self.assertGreaterEqual(c, 0, f"d={d}, x={x}")
                self.assertLess(c, 1 << d, f"d={d}, x={x}")

    def test_error_bounds(self):
        """Decompression error should be bounded.

        For compress/decompress with parameter d, the error
        |decompress(d, compress(d, x)) - x| mod Q should be at most
        round(Q / 2^(d+1)).
        """
        for d in [1, 4, 10]:
            max_error = round(Q / (1 << (d + 1)))
            for x in range(0, Q, max(1, Q // 100)):  # Sample for speed
                c = compress(d, x)
                x_prime = decompress(d, c)
                # Error in modular sense
                diff = (x_prime - x) % Q
                error = min(diff, Q - diff)
                self.assertLessEqual(
                    error, max_error + 1,
                    f"d={d}, x={x}, error={error}, max={max_error}",
                )

    def test_compress_zero(self):
        self.assertEqual(compress(4, 0), 0)

    def test_decompress_zero(self):
        self.assertEqual(decompress(4, 0), 0)


class TestParams(unittest.TestCase):
    """Test parameter set size formulas."""

    def test_ek_size(self):
        self.assertEqual(ML_KEM_512.ek_size, 384 * 2 + 32)
        self.assertEqual(ML_KEM_768.ek_size, 384 * 3 + 32)
        self.assertEqual(ML_KEM_1024.ek_size, 384 * 4 + 32)

    def test_dk_size(self):
        self.assertEqual(ML_KEM_512.dk_size, 768 * 2 + 96)
        self.assertEqual(ML_KEM_768.dk_size, 768 * 3 + 96)
        self.assertEqual(ML_KEM_1024.dk_size, 768 * 4 + 96)

    def test_ct_size(self):
        self.assertEqual(ML_KEM_512.ct_size, 32 * (10 * 2 + 4))
        self.assertEqual(ML_KEM_768.ct_size, 32 * (10 * 3 + 4))
        self.assertEqual(ML_KEM_1024.ct_size, 32 * (11 * 4 + 5))

    def test_names(self):
        self.assertEqual(ML_KEM_512.name, "ML-KEM-512")
        self.assertEqual(ML_KEM_768.name, "ML-KEM-768")
        self.assertEqual(ML_KEM_1024.name, "ML-KEM-1024")


if __name__ == "__main__":
    unittest.main()
