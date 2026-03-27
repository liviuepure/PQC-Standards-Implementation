// Package ntt implements the Number Theoretic Transform for ML-KEM (FIPS 203).
//
// This includes the forward NTT (Algorithm 9), inverse NTT (Algorithm 10),
// pointwise NTT multiplication (Algorithm 11), and base-case multiply
// (Algorithm 12) as specified in FIPS 203.
package ntt

import (
	"github.com/baron-chain/PQC-Standards-Implementation/go/internal/field"
)

// Zetas contains the precomputed twiddle factors for the NTT.
// Zetas[i] = 17^BitRev7(i) mod 3329, computed at compile time.
var Zetas = [128]uint16{
	1, 1729, 2580, 3289, 2642, 630, 1897, 848,
	1062, 1919, 193, 797, 2786, 3260, 569, 1746,
	296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
	1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
	289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
	650, 1977, 2513, 632, 2865, 33, 1320, 1915,
	2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
	2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
	17, 2761, 583, 2649, 1637, 723, 2288, 1100,
	1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
	1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
	939, 2308, 2437, 2388, 733, 2337, 268, 641,
	1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
	1063, 319, 2773, 757, 2099, 561, 2466, 2594,
	2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
	1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
}

// NTT performs the in-place forward Number Theoretic Transform on f.
// This is Algorithm 9 of FIPS 203.
func NTT(f *[256]field.Element) {
	k := 1
	for length := 128; length >= 2; length /= 2 {
		for start := 0; start < 256; start += 2 * length {
			zeta := field.New(Zetas[k])
			k++
			for j := start; j < start+length; j++ {
				t := zeta.Mul(f[j+length])
				f[j+length] = f[j].Sub(t)
				f[j] = f[j].Add(t)
			}
		}
	}
}

// NTTInverse performs the in-place inverse NTT on f.
// This is Algorithm 10 of FIPS 203.
func NTTInverse(f *[256]field.Element) {
	k := 127
	for length := 2; length <= 128; length *= 2 {
		for start := 0; start < 256; start += 2 * length {
			zeta := field.New(Zetas[k])
			k--
			for j := start; j < start+length; j++ {
				t := f[j]
				f[j] = t.Add(f[j+length])
				f[j+length] = zeta.Mul(f[j+length].Sub(t))
			}
		}
	}
	// Multiply every coefficient by 128^{-1} mod q = 3303.
	invN := field.New(3303)
	for i := 0; i < 256; i++ {
		f[i] = f[i].Mul(invN)
	}
}

// MultiplyNTTs computes the pointwise product of two NTT-domain polynomials.
// This is Algorithm 11 of FIPS 203.
func MultiplyNTTs(fHat, gHat *[256]field.Element) [256]field.Element {
	var h [256]field.Element
	for i := 0; i < 64; i++ {
		// First pair: indices (4i, 4i+1) with gamma = Zetas[64+i].
		gamma := field.New(Zetas[64+i])
		c0, c1 := baseCaseMultiply(
			fHat[4*i], fHat[4*i+1],
			gHat[4*i], gHat[4*i+1],
			gamma,
		)
		h[4*i] = c0
		h[4*i+1] = c1

		// Second pair: indices (4i+2, 4i+3) with gamma = -Zetas[64+i].
		c0, c1 = baseCaseMultiply(
			fHat[4*i+2], fHat[4*i+3],
			gHat[4*i+2], gHat[4*i+3],
			gamma.Neg(),
		)
		h[4*i+2] = c0
		h[4*i+3] = c1
	}
	return h
}

// baseCaseMultiply performs the degree-1 polynomial multiplication modulo
// (X^2 - gamma). This is Algorithm 12 of FIPS 203.
//
// Given a(X) = a0 + a1*X and b(X) = b0 + b1*X, it computes:
//
//	c0 = a0*b0 + a1*b1*gamma
//	c1 = a0*b1 + a1*b0
func baseCaseMultiply(a0, a1, b0, b1, gamma field.Element) (field.Element, field.Element) {
	c0 := a0.Mul(b0).Add(a1.Mul(b1).Mul(gamma))
	c1 := a0.Mul(b1).Add(a1.Mul(b0))
	return c0, c1
}
