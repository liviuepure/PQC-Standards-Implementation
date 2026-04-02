"""Tests for the FN-DSA (FIPS 206 / FALCON) Python implementation."""
import pytest
import fndsa


@pytest.mark.parametrize("p", [
    fndsa.FNDSA512, fndsa.FNDSA1024,
    fndsa.FNDSAPadded512, fndsa.FNDSAPadded1024,
])
def test_param_sizes(p):
    assert p.n in (512, 1024)
    assert p.pk_size > 0 and p.sk_size > 0 and p.sig_size > 0


@pytest.mark.parametrize("p", [fndsa.FNDSA512, fndsa.FNDSAPadded512])
def test_roundtrip(p):
    pk, sk = fndsa.keygen(p)
    assert len(pk) == p.pk_size
    assert len(sk) == p.sk_size

    msg = b"test message for FN-DSA"
    sig = fndsa.sign(sk, msg, p)

    if p.padded:
        assert len(sig) == p.sig_size
    else:
        assert len(sig) <= p.sig_size

    assert fndsa.verify(pk, msg, sig, p), "valid signature must verify"

    # Wrong message must fail
    assert not fndsa.verify(pk, b"wrong", sig, p), "wrong message must fail"

    # Tampered signature must fail
    t = bytearray(sig)
    t[min(42, len(t) - 1)] ^= 0x01
    assert not fndsa.verify(pk, msg, bytes(t), p), "tampered signature must fail"


def test_interop_vectors():
    import json
    import binascii
    import os

    for pname, p in [("FN-DSA-512", fndsa.FNDSA512), ("FN-DSA-1024", fndsa.FNDSA1024)]:
        path = os.path.join(
            os.path.dirname(__file__),
            f"../../test-vectors/fn-dsa/{pname}.json"
        )
        if not os.path.exists(path):
            pytest.skip(f"vector file not found: {path}")

        with open(path) as f:
            data = json.load(f)

        for v in data["vectors"]:
            pk = binascii.unhexlify(v["pk"])
            msg = binascii.unhexlify(v["msg"])
            sig = binascii.unhexlify(v["sig"])
            assert fndsa.verify(pk, msg, sig, p), f"count={v['count']}: verify failed"
