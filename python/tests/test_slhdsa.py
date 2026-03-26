"""Tests for SLH-DSA digital signature algorithm (FIPS 205)."""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from slhdsa.slhdsa import keygen, sign, verify
from slhdsa.params import SLH_DSA_SHAKE_128f


class TestRoundtripSHAKE128f(unittest.TestCase):
    """Test sign/verify round-trip for SLH-DSA-SHAKE-128f."""

    def test_roundtrip(self):
        params = SLH_DSA_SHAKE_128f
        pk, sk = keygen(params)
        msg = b"Test message for SLH-DSA"
        sig = sign(sk, msg, params)
        self.assertTrue(verify(pk, msg, sig, params),
                        "Valid signature should be accepted")

    def test_roundtrip_empty_message(self):
        params = SLH_DSA_SHAKE_128f
        pk, sk = keygen(params)
        msg = b""
        sig = sign(sk, msg, params)
        self.assertTrue(verify(pk, msg, sig, params),
                        "Valid signature on empty message should be accepted")


class TestSignatureSize(unittest.TestCase):
    """Test that signature has the expected size."""

    def test_sig_size(self):
        params = SLH_DSA_SHAKE_128f
        pk, sk = keygen(params)
        msg = b"Size check"
        sig = sign(sk, msg, params)
        self.assertEqual(len(sig), params.sig_size,
                         f"Signature size {len(sig)} != expected {params.sig_size}")

    def test_pk_size(self):
        params = SLH_DSA_SHAKE_128f
        pk, sk = keygen(params)
        self.assertEqual(len(pk), params.pk_size,
                         f"PK size {len(pk)} != expected {params.pk_size}")

    def test_sk_size(self):
        params = SLH_DSA_SHAKE_128f
        pk, sk = keygen(params)
        self.assertEqual(len(sk), params.sk_size,
                         f"SK size {len(sk)} != expected {params.sk_size}")


class TestRejectTampered(unittest.TestCase):
    """Test that tampered signatures and messages are rejected."""

    def test_tampered_signature(self):
        params = SLH_DSA_SHAKE_128f
        pk, sk = keygen(params)
        msg = b"Original message"
        sig = sign(sk, msg, params)

        # Tamper with signature
        sig_tampered = bytearray(sig)
        sig_tampered[len(sig) // 2] ^= 0xFF
        sig_tampered = bytes(sig_tampered)

        self.assertFalse(verify(pk, msg, sig_tampered, params),
                         "Tampered signature should be rejected")

    def test_tampered_message(self):
        params = SLH_DSA_SHAKE_128f
        pk, sk = keygen(params)
        msg = b"Original message"
        sig = sign(sk, msg, params)

        msg_tampered = b"Tampered message"
        self.assertFalse(verify(pk, msg_tampered, sig, params),
                         "Signature should be rejected for wrong message")

    def test_wrong_key(self):
        params = SLH_DSA_SHAKE_128f
        pk1, sk1 = keygen(params)
        pk2, sk2 = keygen(params)
        msg = b"Test message"
        sig = sign(sk1, msg, params)

        self.assertFalse(verify(pk2, msg, sig, params),
                         "Signature should be rejected for wrong public key")


if __name__ == "__main__":
    unittest.main()
