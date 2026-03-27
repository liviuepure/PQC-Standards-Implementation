"""Tests for Hybrid KEM schemes."""

import sys
import os
import unittest

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hybrid.hybrid_kem import (
    HybridScheme,
    X25519_MLKEM768,
    ECDHP256_MLKEM768,
    X25519_MLKEM1024,
    ECDHP384_MLKEM1024,
    hybrid_keygen,
    hybrid_encaps,
    hybrid_decaps,
)
from hybrid.x25519 import x25519, x25519_keygen, BASEPOINT


class TestX25519(unittest.TestCase):
    """Test the pure Python X25519 implementation."""

    def test_keygen_roundtrip(self):
        """Key generation and DH roundtrip."""
        pk_a, sk_a = x25519_keygen()
        pk_b, sk_b = x25519_keygen()
        ss_a = x25519(sk_a, pk_b)
        ss_b = x25519(sk_b, pk_a)
        self.assertEqual(ss_a, ss_b)
        self.assertEqual(len(ss_a), 32)


class TestHybridKEM(unittest.TestCase):
    """Test hybrid KEM roundtrips."""

    def _test_roundtrip(self, scheme: HybridScheme):
        kp = hybrid_keygen(scheme)
        enc = hybrid_encaps(scheme, kp.ek, kp.classical_ek_size)
        ss = hybrid_decaps(
            scheme, kp.dk, enc.ciphertext,
            kp.classical_dk_size, enc.classical_ct_size,
        )
        self.assertEqual(len(enc.shared_secret), 32,
                         f"{scheme.name}: shared secret should be 32 bytes")
        self.assertEqual(enc.shared_secret, ss,
                         f"{scheme.name}: roundtrip failed")

    def test_x25519_mlkem768_roundtrip(self):
        self._test_roundtrip(X25519_MLKEM768)

    def test_x25519_mlkem1024_roundtrip(self):
        self._test_roundtrip(X25519_MLKEM1024)

    def test_different_keys_different_secrets(self):
        kp1 = hybrid_keygen(X25519_MLKEM768)
        kp2 = hybrid_keygen(X25519_MLKEM768)
        enc1 = hybrid_encaps(X25519_MLKEM768, kp1.ek, kp1.classical_ek_size)
        enc2 = hybrid_encaps(X25519_MLKEM768, kp2.ek, kp2.classical_ek_size)
        self.assertNotEqual(enc1.shared_secret, enc2.shared_secret)

    def test_multiple_encaps_same_key(self):
        kp = hybrid_keygen(X25519_MLKEM768)
        enc1 = hybrid_encaps(X25519_MLKEM768, kp.ek, kp.classical_ek_size)
        enc2 = hybrid_encaps(X25519_MLKEM768, kp.ek, kp.classical_ek_size)
        self.assertNotEqual(enc1.shared_secret, enc2.shared_secret)

        ss1 = hybrid_decaps(
            X25519_MLKEM768, kp.dk, enc1.ciphertext,
            kp.classical_dk_size, enc1.classical_ct_size,
        )
        ss2 = hybrid_decaps(
            X25519_MLKEM768, kp.dk, enc2.ciphertext,
            kp.classical_dk_size, enc2.classical_ct_size,
        )
        self.assertEqual(enc1.shared_secret, ss1)
        self.assertEqual(enc2.shared_secret, ss2)


class TestHybridKEMNIST(unittest.TestCase):
    """Test NIST curve hybrid KEM schemes (requires 'cryptography' package)."""

    def setUp(self):
        try:
            import cryptography
            self.has_crypto = True
        except ImportError:
            self.has_crypto = False

    def test_ecdhp256_mlkem768_roundtrip(self):
        if not self.has_crypto:
            self.skipTest("cryptography package not installed")
        kp = hybrid_keygen(ECDHP256_MLKEM768)
        enc = hybrid_encaps(ECDHP256_MLKEM768, kp.ek, kp.classical_ek_size)
        ss = hybrid_decaps(
            ECDHP256_MLKEM768, kp.dk, enc.ciphertext,
            kp.classical_dk_size, enc.classical_ct_size,
        )
        self.assertEqual(enc.shared_secret, ss)

    def test_ecdhp384_mlkem1024_roundtrip(self):
        if not self.has_crypto:
            self.skipTest("cryptography package not installed")
        kp = hybrid_keygen(ECDHP384_MLKEM1024)
        enc = hybrid_encaps(ECDHP384_MLKEM1024, kp.ek, kp.classical_ek_size)
        ss = hybrid_decaps(
            ECDHP384_MLKEM1024, kp.dk, enc.ciphertext,
            kp.classical_dk_size, enc.classical_ct_size,
        )
        self.assertEqual(enc.shared_secret, ss)


if __name__ == "__main__":
    unittest.main()
