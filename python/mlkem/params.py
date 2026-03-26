"""ML-KEM parameter sets per FIPS 203."""

from dataclasses import dataclass


@dataclass(frozen=True)
class MLKEMParams:
    name: str
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int

    @property
    def ek_size(self) -> int:
        return 384 * self.k + 32

    @property
    def dk_size(self) -> int:
        return 768 * self.k + 96

    @property
    def ct_size(self) -> int:
        return 32 * (self.du * self.k + self.dv)


ML_KEM_512 = MLKEMParams(name="ML-KEM-512", k=2, eta1=3, eta2=2, du=10, dv=4)
ML_KEM_768 = MLKEMParams(name="ML-KEM-768", k=3, eta1=2, eta2=2, du=10, dv=4)
ML_KEM_1024 = MLKEMParams(name="ML-KEM-1024", k=4, eta1=2, eta2=2, du=11, dv=5)
