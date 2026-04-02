"""Tests for the FN-DSA (FIPS 206 / FALCON) Python implementation."""
from __future__ import annotations
import unittest
import fndsa


class TestFnDsaParamSizes(unittest.TestCase):
    def test_fndsa512(self):
        p = fndsa.FNDSA512
        self.assertIn(p.n, (512, 1024))
        self.assertGreater(p.pk_size, 0)
        self.assertGreater(p.sk_size, 0)
        self.assertGreater(p.sig_size, 0)

    def test_fndsa1024(self):
        p = fndsa.FNDSA1024
        self.assertIn(p.n, (512, 1024))
        self.assertGreater(p.pk_size, 0)

    def test_fndsa_padded512(self):
        p = fndsa.FNDSAPadded512
        self.assertTrue(p.padded)
        self.assertGreater(p.sig_size, 0)

    def test_fndsa_padded1024(self):
        p = fndsa.FNDSAPadded1024
        self.assertTrue(p.padded)
        self.assertGreater(p.sig_size, 0)


class TestFnDsaInteropVectors(unittest.TestCase):
    def test_interop_vectors(self):
        import json
        import binascii
        import os

        any_ran = False
        for pname, p in [("FN-DSA-512", fndsa.FNDSA512), ("FN-DSA-1024", fndsa.FNDSA1024)]:
            path = os.path.join(
                os.path.dirname(__file__),
                f"../../test-vectors/fn-dsa/{pname}.json"
            )
            if not os.path.exists(path):
                continue

            with open(path) as f:
                data = json.load(f)

            for v in data["vectors"]:
                pk = binascii.unhexlify(v["pk"])
                msg = binascii.unhexlify(v["msg"])
                sig = binascii.unhexlify(v["sig"])
                self.assertTrue(
                    fndsa.verify(pk, msg, sig, p),
                    f"{pname} count={v['count']}: verify failed"
                )
            any_ran = True

        self.assertTrue(any_ran, "No FN-DSA test vector files found")


if __name__ == "__main__":
    unittest.main()
