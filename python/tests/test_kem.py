"""Tests for ML-KEM key encapsulation mechanism."""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mlkem.kem import keygen, encaps, decaps
from mlkem.params import ML_KEM_512, ML_KEM_768, ML_KEM_1024


class TestKEMRoundTrip(unittest.TestCase):
    """Test ML-KEM round-trip for all parameter sets."""

    def _test_roundtrip(self, params):
        ek, dk = keygen(params)
        self.assertEqual(len(ek), params.ek_size)
        self.assertEqual(len(dk), params.dk_size)

        K_send, c = encaps(ek, params)
        self.assertEqual(len(c), params.ct_size)
        self.assertEqual(len(K_send), 32)

        K_recv = decaps(dk, c, params)
        self.assertEqual(len(K_recv), 32)
        self.assertEqual(K_send, K_recv)

    def test_roundtrip_512(self):
        self._test_roundtrip(ML_KEM_512)

    def test_roundtrip_768(self):
        self._test_roundtrip(ML_KEM_768)

    def test_roundtrip_1024(self):
        self._test_roundtrip(ML_KEM_1024)


class TestImplicitRejection(unittest.TestCase):
    """Test implicit rejection with tampered ciphertext."""

    def test_tampered_ciphertext_512(self):
        params = ML_KEM_512
        ek, dk = keygen(params)
        K_send, c = encaps(ek, params)

        # Tamper with ciphertext
        c_tampered = bytearray(c)
        c_tampered[0] ^= 0xFF
        c_tampered = bytes(c_tampered)

        K_recv = decaps(dk, c_tampered, params)
        # Should get a different key (implicit rejection)
        self.assertNotEqual(K_send, K_recv)
        # But should still return a 32-byte key
        self.assertEqual(len(K_recv), 32)

    def test_implicit_rejection_deterministic(self):
        """Implicit rejection should be deterministic for the same dk and c."""
        params = ML_KEM_512
        ek, dk = keygen(params)
        _, c = encaps(ek, params)

        c_tampered = bytearray(c)
        c_tampered[len(c) // 2] ^= 0x01
        c_tampered = bytes(c_tampered)

        K1 = decaps(dk, c_tampered, params)
        K2 = decaps(dk, c_tampered, params)
        self.assertEqual(K1, K2)


class TestEKValidation(unittest.TestCase):
    """Test encapsulation key validation."""

    def test_invalid_ek(self):
        """Setting ek bytes to 0xFF should cause validation failure."""
        params = ML_KEM_512
        # Create an ek with all 0xFF bytes (will decode to values >= Q)
        bad_ek = bytes([0xFF] * params.ek_size)
        with self.assertRaises(ValueError):
            encaps(bad_ek, params)

    def test_valid_ek_passes(self):
        """A properly generated ek should pass validation."""
        params = ML_KEM_512
        ek, _ = keygen(params)
        # Should not raise
        K, c = encaps(ek, params)
        self.assertEqual(len(K), 32)
        self.assertEqual(len(c), params.ct_size)


class TestMultipleRoundTrips(unittest.TestCase):
    """Test multiple encapsulations with the same key pair."""

    def test_multiple_encaps_512(self):
        params = ML_KEM_512
        ek, dk = keygen(params)

        for _ in range(5):
            K_send, c = encaps(ek, params)
            K_recv = decaps(dk, c, params)
            self.assertEqual(K_send, K_recv)

    def test_different_shared_secrets(self):
        """Each encapsulation should produce a different shared secret."""
        params = ML_KEM_512
        ek, dk = keygen(params)

        secrets = set()
        for _ in range(5):
            K_send, c = encaps(ek, params)
            K_recv = decaps(dk, c, params)
            self.assertEqual(K_send, K_recv)
            secrets.add(K_send)

        # All 5 shared secrets should be unique (with overwhelming probability)
        self.assertEqual(len(secrets), 5)


if __name__ == "__main__":
    unittest.main()
