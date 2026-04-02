package fndsa

import (
	"math"
	"math/cmplx"
)

// Complex FFT/IFFT/SplitFFT/MergeFFT for FN-DSA (FIPS 206 / FALCON).
//
// These operate over C[x]/(x^n+1), evaluating polynomials at the 2n-th
// primitive roots of unity: ω_j = exp(iπ(2j+1)/n) for j = 0..n-1.
//
// The FFT uses a Cooley–Tukey butterfly identical in structure to the NTT,
// but with complex twiddle factors:
//   w_k = exp(iπ · bit_rev(k, log2(n)) / n)
//
// The output is in bit-reversed order (consistent with IFFT, SplitFFT, MergeFFT).
//
// SplitFFT decomposes f(x) = f0(x²) + x·f1(x²) in the FFT domain.
// MergeFFT is the inverse of SplitFFT.

// fftBitRev reverses the low logn bits of k.
func fftBitRev(k, logn int) int {
	r := 0
	for i := 0; i < logn; i++ {
		r = (r << 1) | (k & 1)
		k >>= 1
	}
	return r
}

// fftLogN returns log2(n); panics if n is not a power of two.
func fftLogN(n int) int {
	logn := 0
	for t := n; t > 1; t >>= 1 {
		logn++
	}
	return logn
}

// FFT performs an in-place forward negacyclic complex FFT over C[x]/(x^n+1).
// f is a slice of n complex128 values representing polynomial coefficients.
// After FFT, f[j] holds the evaluation of the polynomial at the (2j+1)-th 2n-th
// root of unity (in bit-reversed index order).
// n must be a power of two (4 ≤ n ≤ 1024).
func FFT(f []complex128, n int) {
	logn := fftLogN(n)

	k := 0
	for length := n >> 1; length >= 1; length >>= 1 {
		for start := 0; start < n; start += 2 * length {
			k++
			brk := fftBitRev(k, logn)
			// Twiddle: exp(iπ · bit_rev(k) / n)
			w := cmplx.Exp(complex(0, math.Pi*float64(brk)/float64(n)))
			for j := start; j < start+length; j++ {
				t := w * f[j+length]
				f[j+length] = f[j] - t
				f[j] = f[j] + t
			}
		}
	}
}

// IFFT performs an in-place inverse negacyclic complex FFT over C[x]/(x^n+1).
// It is the inverse of FFT: IFFT(FFT(f)) = f (within floating-point precision).
// The result is scaled by 1/n.
// n must be a power of two (4 ≤ n ≤ 1024).
func IFFT(f []complex128, n int) {
	logn := fftLogN(n)

	k := n
	for length := 1; length < n; length <<= 1 {
		// Process blocks in reverse order to undo FFT butterflies exactly.
		for start := n - 2*length; start >= 0; start -= 2 * length {
			k--
			brk := fftBitRev(k, logn)
			// Inverse twiddle: exp(−iπ · bit_rev(k) / n)
			wInv := cmplx.Exp(complex(0, -math.Pi*float64(brk)/float64(n)))
			for j := start; j < start+length; j++ {
				t := f[j]
				f[j] = t + f[j+length]
				f[j+length] = wInv * (t - f[j+length])
			}
		}
	}

	// Scale by 1/n.
	invN := complex(1.0/float64(n), 0)
	for i := range f {
		f[i] *= invN
	}
}

// SplitFFT splits an n-element FFT-domain polynomial f (in bit-reversed order)
// into two (n/2)-element FFT-domain polynomials f0 and f1, where:
//
//	f(x) = f0(x²) + x·f1(x²)
//
// This exploits the pairing structure of the bit-reversed FFT output:
// positions (2k, 2k+1) in the bit-reversed layout correspond to evaluations at
// conjugate pairs (ω_j, ω_{j+n/2}) = (ω_j, -ω_j) in natural order.
//
// Formula (per FALCON spec §3.7.1):
//
//	f0[k] = (f[2k] + f[2k+1]) / 2
//	f1[k] = (f[2k] - f[2k+1]) / (2 · ω_j)
//
// where ω_j = exp(iπ(2j+1)/n) with j = bit_rev(k, log2(n)−1).
func SplitFFT(f []complex128, n int) (f0, f1 []complex128) {
	logn := fftLogN(n)
	h := n / 2
	f0 = make([]complex128, h)
	f1 = make([]complex128, h)
	for k := 0; k < h; k++ {
		// Natural index j corresponding to bit-reversed position k in the n/2 output.
		j := fftBitRev(k, logn-1)
		// Twiddle: ω_j = exp(iπ(2j+1)/n)
		omegaJ := cmplx.Exp(complex(0, math.Pi*float64(2*j+1)/float64(n)))
		a := f[2*k]
		b := f[2*k+1]
		f0[k] = (a + b) / 2
		f1[k] = (a - b) / (2 * omegaJ)
	}
	return f0, f1
}

// MergeFFT is the inverse of SplitFFT. Given two (n/2)-element FFT-domain
// polynomials f0 and f1, it reconstructs the n-element FFT-domain polynomial f
// such that f(x) = f0(x²) + x·f1(x²).
//
// Formula (inverse of SplitFFT):
//
//	f[2k]   = f0[k] + ω_j · f1[k]
//	f[2k+1] = f0[k] − ω_j · f1[k]
//
// where ω_j = exp(iπ(2j+1)/n) with j = bit_rev(k, log2(n)−1).
func MergeFFT(f0, f1 []complex128, n int) []complex128 {
	logn := fftLogN(n)
	h := n / 2
	f := make([]complex128, n)
	for k := 0; k < h; k++ {
		j := fftBitRev(k, logn-1)
		omegaJ := cmplx.Exp(complex(0, math.Pi*float64(2*j+1)/float64(n)))
		t := omegaJ * f1[k]
		f[2*k] = f0[k] + t
		f[2*k+1] = f0[k] - t
	}
	return f
}
