import pytest
from hqc import HQC128, HQC192, HQC256, key_gen, encaps, decaps


@pytest.mark.parametrize("p", [HQC128, HQC192, HQC256])
def test_roundtrip(p):
    pk, sk = key_gen(p)
    assert len(pk) == p.pk_size
    assert len(sk) == p.sk_size
    ct, ss1 = encaps(pk, p)
    assert len(ct) == p.ct_size
    assert len(ss1) == 64
    ss2 = decaps(sk, ct, p)
    assert ss1 == ss2


@pytest.mark.parametrize("p", [HQC128, HQC192, HQC256])
def test_corrupted_ciphertext(p):
    pk, sk = key_gen(p)
    ct, ss1 = encaps(pk, p)
    # Flip a bit in the ciphertext
    ct_bad = bytearray(ct)
    ct_bad[10] ^= 0x01
    ss2 = decaps(sk, bytes(ct_bad), p)
    # Should NOT match (FO rejection)
    assert ss1 != ss2
