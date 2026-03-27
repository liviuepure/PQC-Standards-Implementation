"""Tests for composite signature schemes."""

import struct
import unittest

from composite.composite_sig import (
    CompositeScheme,
    MLDSA65_ED25519,
    MLDSA87_ED25519,
    MLDSA44_ED25519,
    key_gen,
    sign,
    verify,
)
from composite.ed25519_pure import (
    keygen as ed25519_keygen,
    sign as ed25519_sign,
    verify as ed25519_verify,
)


class TestEd25519Pure(unittest.TestCase):
    def test_roundtrip(self):
        pk, sk = ed25519_keygen()
        msg = b"Ed25519 test message"
        sig = ed25519_sign(sk, msg)
        self.assertTrue(ed25519_verify(pk, msg, sig), "Ed25519 roundtrip failed")

    def test_wrong_message(self):
        pk, sk = ed25519_keygen()
        sig = ed25519_sign(sk, b"Original")
        self.assertFalse(ed25519_verify(pk, b"Tampered", sig))

    def test_deterministic(self):
        seed = bytes(range(32))
        pk1, sk1 = ed25519_keygen(seed)
        pk2, sk2 = ed25519_keygen(seed)
        self.assertEqual(pk1, pk2)
        sig1 = ed25519_sign(sk1, b"Hello")
        sig2 = ed25519_sign(sk2, b"Hello")
        self.assertEqual(sig1, sig2)


class TestCompositeMLDSA44Ed25519(unittest.TestCase):
    scheme = MLDSA44_ED25519

    def test_roundtrip(self):
        kp = key_gen(self.scheme)
        msg = b"Hello ML-DSA-44+Ed25519"
        sig = sign(kp, msg)
        self.assertTrue(verify(self.scheme, kp.pk, msg, sig))

    def test_wrong_message(self):
        kp = key_gen(self.scheme)
        sig = sign(kp, b"Original")
        self.assertFalse(verify(self.scheme, kp.pk, b"Tampered", sig))

    def test_tamper_classical(self):
        kp = key_gen(self.scheme)
        msg = b"Tamper classical"
        sig = bytearray(sign(kp, msg))
        if len(sig) > 4:
            sig[4] ^= 0xFF
        self.assertFalse(verify(self.scheme, kp.pk, msg, bytes(sig)))

    def test_tamper_pq(self):
        kp = key_gen(self.scheme)
        msg = b"Tamper PQ"
        sig = bytearray(sign(kp, msg))
        sig[-1] ^= 0xFF
        self.assertFalse(verify(self.scheme, kp.pk, msg, bytes(sig)))


class TestCompositeMLDSA65Ed25519(unittest.TestCase):
    scheme = MLDSA65_ED25519

    def test_roundtrip(self):
        kp = key_gen(self.scheme)
        msg = b"Hello ML-DSA-65+Ed25519"
        sig = sign(kp, msg)
        self.assertTrue(verify(self.scheme, kp.pk, msg, sig))

    def test_wrong_message(self):
        kp = key_gen(self.scheme)
        sig = sign(kp, b"Original")
        self.assertFalse(verify(self.scheme, kp.pk, b"Tampered", sig))


class TestCompositeMLDSA87Ed25519(unittest.TestCase):
    scheme = MLDSA87_ED25519

    def test_roundtrip(self):
        kp = key_gen(self.scheme)
        msg = b"Hello ML-DSA-87+Ed25519"
        sig = sign(kp, msg)
        self.assertTrue(verify(self.scheme, kp.pk, msg, sig))

    def test_wrong_message(self):
        kp = key_gen(self.scheme)
        sig = sign(kp, b"Original")
        self.assertFalse(verify(self.scheme, kp.pk, b"Tampered", sig))


if __name__ == '__main__':
    unittest.main()
