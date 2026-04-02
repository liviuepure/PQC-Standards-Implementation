"""HQC (Hamming Quasi-Cyclic) KEM - Pure Python implementation."""

from hqc.params import HQC_128, HQC_192, HQC_256
from hqc.kem import key_gen, encaps, decaps

# Aliases matching test expectations
HQC128 = HQC_128
HQC192 = HQC_192
HQC256 = HQC_256

__all__ = [
    "HQC_128",
    "HQC_192",
    "HQC_256",
    "HQC128",
    "HQC192",
    "HQC256",
    "key_gen",
    "encaps",
    "decaps",
]
