"""Tests for the HQC (Hamming Quasi-Cyclic) Python implementation."""
from __future__ import annotations
import unittest
from hqc import HQC128, HQC192, HQC256, key_gen, encaps, decaps


class TestHqcRoundtrip(unittest.TestCase):
    def _roundtrip(self, p):
        pk, sk = key_gen(p)
        self.assertEqual(len(pk), p.pk_size)
        self.assertEqual(len(sk), p.sk_size)
        ct, ss1 = encaps(pk, p)
        self.assertEqual(len(ct), p.ct_size)
        self.assertEqual(len(ss1), 64)
        ss2 = decaps(sk, ct, p)
        self.assertEqual(ss1, ss2)

    def test_hqc128(self):
        self._roundtrip(HQC128)

    def test_hqc192(self):
        self._roundtrip(HQC192)

    def test_hqc256(self):
        self._roundtrip(HQC256)


class TestHqcCorruptedCiphertext(unittest.TestCase):
    def _corrupted(self, p):
        pk, sk = key_gen(p)
        ct, ss1 = encaps(pk, p)
        ct_bad = bytearray(ct)
        ct_bad[10] ^= 0x01
        ss2 = decaps(sk, bytes(ct_bad), p)
        self.assertNotEqual(ss1, ss2)

    def test_hqc128(self):
        self._corrupted(HQC128)

    def test_hqc192(self):
        self._corrupted(HQC192)

    def test_hqc256(self):
        self._corrupted(HQC256)


if __name__ == "__main__":
    unittest.main()
