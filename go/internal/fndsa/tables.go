package fndsa

// Precomputed NTT zeta tables for n=512 (logn=9) and n=1024 (logn=10).
//
// Forward tables:
//   nttZetas512[k]     = psi_512^bitrev(k, 9)   mod Q, for k in [0, 512)
//   nttZetas1024[k]    = psi_1024^bitrev(k, 10)  mod Q, for k in [0, 1024)
//
// Inverse tables (modular inverse of each forward entry):
//   nttZetasInv512[k]  = (psi_512^bitrev(k, 9))^{-1}   mod Q
//   nttZetasInv1024[k] = (psi_1024^bitrev(k, 10))^{-1} mod Q
//
// where psi_n = 11^((Q-1)/(2n)) mod Q is the primitive 2n-th root of unity:
//   psi_512  = 11^12 mod 12289  (order 1024, psi_512^512  ≡ -1 mod Q)
//   psi_1024 = 11^6  mod 12289  (order 2048, psi_1024^1024 ≡ -1 mod Q)
//
// These tables are used by NTT and INTT to avoid repeated modular exponentiation.

var nttZetas512 [512]int32
var nttZetasInv512 [512]int32
var nttZetas1024 [1024]int32
var nttZetasInv1024 [1024]int32

func init() {
	// Populate nttZetas512 and nttZetasInv512.
	// psi_512 = 11^((12289-1)/(2*512)) = 11^12 mod 12289
	psi512 := int64(nttPow(11, int64((Q-1)/(2*512))))
	for k := 0; k < 512; k++ {
		br := nttBitRev(k, 9)
		z := nttPow(psi512, int64(br))
		nttZetas512[k] = z
		nttZetasInv512[k] = nttPow(int64(z), int64(Q-2))
	}

	// Populate nttZetas1024 and nttZetasInv1024.
	// psi_1024 = 11^((12289-1)/(2*1024)) = 11^6 mod 12289
	psi1024 := int64(nttPow(11, int64((Q-1)/(2*1024))))
	for k := 0; k < 1024; k++ {
		br := nttBitRev(k, 10)
		z := nttPow(psi1024, int64(br))
		nttZetas1024[k] = z
		nttZetasInv1024[k] = nttPow(int64(z), int64(Q-2))
	}
}
