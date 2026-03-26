// Package ntt implements the Number Theoretic Transform for ML-KEM (FIPS 203).
//
// This includes the forward NTT (Algorithm 9), inverse NTT (Algorithm 10),
// pointwise NTT multiplication (Algorithm 11), and base-case multiply
// (Algorithm 12) as specified in FIPS 203.
package ntt

import (
	"github.com/baron-chain/PQC-Standards-Implementation/go/internal/field"
)

// BitRev7 reverses the 7 least significant bits of x.
func BitRev7(x uint8) uint8 {
	var r uint8
	for i := 0; i < 7; i++ {
		r = (r << 1) | (x & 1)
		x >>= 1
	}
	return r
}

// Zetas contains the precomputed twiddle factors for the NTT.
// Zetas[i] = 17^BitRev7(i) mod 3329.
var Zetas [128]uint16

func init() {
	for i := 0; i < 128; i++ {
		exp := BitRev7(uint8(i))
		Zetas[i] = modExp(17, uint32(exp), field.Q)
	}
}

// modExp computes base^exp mod mod using repeated squaring.
func modExp(base, exp, mod uint32) uint16 {
	result := uint32(1)
	base = base % mod
	for exp > 0 {
		if exp&1 == 1 {
			result = (result * base) % mod
		}
		exp >>= 1
		base = (base * base) % mod
	}
	return uint16(result)
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
