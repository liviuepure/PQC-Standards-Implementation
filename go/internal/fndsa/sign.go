package fndsa

// sign.go implements FN-DSA signing (FIPS 206):
//   - HashToPoint: hash a message to a polynomial in Z_q[x]/(x^n+1)
//   - ffSamplingBabai: Babai nearest-plane lattice sampler over the NTRU basis
//   - SignInternal: full signing with norm-bound retry loop

import (
	"errors"
	"io"
	"math"

	"golang.org/x/crypto/sha3"
)

// HashToPoint hashes msg (which should be salt||message) to a polynomial
// c ∈ Z_q[x]/(x^n+1) with coefficients in [0, Q).
// Uses SHAKE256 extended output, rejection-sampling 16-bit values mod Q.
func HashToPoint(msg []byte, p *Params) []int32 {
	n := p.N
	out := make([]int32, n)
	h := sha3.NewShake256()
	h.Write(msg)

	buf := make([]byte, 2)
	count := 0
	for count < n {
		h.Read(buf)
		v := int32(uint16(buf[0]) | uint16(buf[1])<<8)
		// Rejection sampling: discard values >= 5*Q to get near-uniform mod Q.
		if v < 5*Q {
			out[count] = v % Q
			count++
		}
	}
	return out
}

// centerModQ reduces v mod Q and centers the result in (-Q/2, Q/2].
func centerModQ(v int32) int32 {
	v = ((v % Q) + Q) % Q
	if v > Q/2 {
		v -= Q
	}
	return v
}

// int32sToFFT converts an integer polynomial to the complex FFT domain.
func int32sToFFT(a []int32, n int) []complex128 {
	f := make([]complex128, n)
	for i, v := range a {
		f[i] = complex(float64(v), 0)
	}
	FFT(f, n)
	return f
}

// roundFFTToInt32s applies IFFT and rounds to nearest integer polynomial.
func roundFFTToInt32s(fft []complex128, n int) []int32 {
	tmp := make([]complex128, n)
	copy(tmp, fft)
	IFFT(tmp, n)
	out := make([]int32, n)
	for i, v := range tmp {
		out[i] = int32(math.Round(real(v)))
	}
	return out
}

// recoverG recovers G from (f, g, F) using the NTRU equation fG - gF = Q.
// Since G coefficients are bounded well below Q/2, computing mod q and
// centering gives the exact integer value.
func recoverG(f, g, F []int32, n int) []int32 {
	// Compute gF mod q in coefficient domain via NTT.
	gModQ := make([]int32, n)
	FModQ := make([]int32, n)
	for i := range g {
		gModQ[i] = ((g[i] % Q) + Q) % Q
		FModQ[i] = ((F[i] % Q) + Q) % Q
	}
	gF := PolyMulNTT(gModQ, FModQ, n)
	// Add Q to constant term (gF + Q corresponds to gF + q·1 in coefficient domain).
	gF[0] = int32((int64(gF[0]) + Q) % Q)

	// Compute f^{-1} mod q via NTT: invert each NTT coefficient using Fermat's little theorem.
	fModQ := make([]int32, n)
	for i, v := range f {
		fModQ[i] = ((v % Q) + Q) % Q
	}
	fNTT := make([]int32, n)
	copy(fNTT, fModQ)
	NTT(fNTT, n)
	for i, v := range fNTT {
		fNTT[i] = nttPow(int64(v), int64(Q-2))
	}
	INTT(fNTT, n)

	// G = (gF + Q) * f^{-1} mod q.
	G := PolyMulNTT(gF, fNTT, n)

	// Center coefficients in (-Q/2, Q/2].
	result := make([]int32, n)
	for i, v := range G {
		if v > Q/2 {
			v -= Q
		}
		result[i] = v
	}
	return result
}

// ffSamplingBabai implements the two-step Babai nearest-plane algorithm for FN-DSA.
//
// The NTRU coset lattice L = {(a,b) : a + b*h ≡ 0 (mod q)} has basis
// B = [[g, -f], [G, -F]] with det(B) = f*G - g*F = q.
//
// We find the lattice vector v ∈ L closest to target (c, 0), and return the
// coset signature s = (c,0) - v:
//
//	s1 = c - v1,  s2 = -v2
//
// The two-step nearest-plane uses the Gram-Schmidt basis.  For each FFT index j,
// the 2×2 complex lattice has basis vectors b0_j = (g_j, -f_j), b1_j = (G_j, -F_j).
// The Gram-Schmidt decomposition:
//
//	b0^* = b0
//	μ10  = <b1, b0^*> / ||b0^*||²   (pointwise complex scalar per FFT index)
//	b1^* = b1 - μ10 * b0^*
//
// Nearest-plane (in reverse GS order):
//
//  1. τ1_j = <t_j, conj(b1^*_j)> / ||b1^*_j||²,   t_j = (c_j, 0)
//     IFFT(τ1), round → z1 ∈ Z[x]/(x^n+1)
//     Update: t'_j = t_j - z1_j * b1_j
//
//  2. τ0_j = <t'_j, conj(b0^*_j)> / ||b0^*_j||²
//     IFFT(τ0), round → z0 ∈ Z[x]/(x^n+1)
//
// Lattice vector: v1_j = z0_j*g_j + z1_j*G_j,  v2_j = -z0_j*f_j - z1_j*F_j
// Signature:      s1_j = c_j - v1_j,            s2_j = -v2_j
//
// This satisfies s1 + s2*h ≡ c (mod q) by the NTRU equation G ≡ F*h (mod q).
func ffSamplingBabai(c, f, g, F, G []int32, n int) (s1, s2 []int32) {
	cFFT := int32sToFFT(c, n)
	fFFT := int32sToFFT(f, n)
	gFFT := int32sToFFT(g, n)
	FFFT := int32sToFFT(F, n)
	GFFT := int32sToFFT(G, n)

	// Gram-Schmidt: compute b1^* = b1 - μ10*b0^* per FFT point.
	// μ10_j = <b1_j, b0_j^*> / ||b0_j^*||²
	//       = (G_j*conj(g_j) + F_j*conj(f_j)) / (|g_j|² + |f_j|²)
	// b1^*_j = (G_j - μ10_j*g_j, -F_j - μ10_j*(-f_j)) = (G_j - μ10_j*g_j, -F_j + μ10_j*f_j)
	b1StarFFT := make([][2]complex128, n) // b1^*_j = [first, second] component
	b1StarNormSqFFT := make([]float64, n)
	for j := range b1StarFFT {
		gj := gFFT[j]
		fj := fFFT[j]
		Gj := GFFT[j]
		Fj := FFFT[j]
		b0NormSq := real(gj)*real(gj) + imag(gj)*imag(gj) + real(fj)*real(fj) + imag(fj)*imag(fj)
		var mu10 complex128
		if b0NormSq != 0 {
			num := Gj*complex(real(gj), -imag(gj)) + Fj*complex(real(fj), -imag(fj))
			mu10 = complex(real(num)/b0NormSq, imag(num)/b0NormSq)
		}
		b1s0 := Gj - mu10*gj
		b1s1 := -Fj + mu10*fj
		b1StarFFT[j] = [2]complex128{b1s0, b1s1}
		b1StarNormSqFFT[j] = real(b1s0)*real(b1s0) + imag(b1s0)*imag(b1s0) +
			real(b1s1)*real(b1s1) + imag(b1s1)*imag(b1s1)
	}

	// ---- Step 1: project (c_j, 0) along b1^*_j ----
	// τ1_j = <(c_j, 0), conj(b1^*_j)> / ||b1^*||²
	//      = c_j * conj(b1^*_j[0]) / ||b1^*||²
	tau1FFT := make([]complex128, n)
	for j := range tau1FFT {
		b1sNorm := b1StarNormSqFFT[j]
		if b1sNorm != 0 {
			b1s0 := b1StarFFT[j][0]
			num := cFFT[j] * complex(real(b1s0), -imag(b1s0))
			tau1FFT[j] = complex(real(num)/b1sNorm, imag(num)/b1sNorm)
		}
	}
	z1 := roundFFTToInt32s(tau1FFT, n)
	z1FFT := int32sToFFT(z1, n)

	// Update target: t'_j = (c_j, 0) - z1_j*(G_j, -F_j) = (c_j - z1_j*G_j, z1_j*F_j)
	cPrimeFFT := make([]complex128, n)
	xPrimeFFT := make([]complex128, n)
	for j := range cPrimeFFT {
		cPrimeFFT[j] = cFFT[j] - z1FFT[j]*GFFT[j]
		xPrimeFFT[j] = z1FFT[j] * FFFT[j]
	}

	// ---- Step 2: project t'_j along b0^*_j = (g_j, -f_j) ----
	// τ0_j = <(c'_j, x'_j), conj((g_j, -f_j))> / (|g_j|² + |f_j|²)
	//      = (c'_j*conj(g_j) + x'_j*conj(-f_j)) / (|g_j|² + |f_j|²)
	//      = (c'_j*conj(g_j) - x'_j*conj(f_j)) / (|g_j|² + |f_j|²)
	tau0FFT := make([]complex128, n)
	for j := range tau0FFT {
		gj := gFFT[j]
		fj := fFFT[j]
		b0NormSq := real(gj)*real(gj) + imag(gj)*imag(gj) + real(fj)*real(fj) + imag(fj)*imag(fj)
		if b0NormSq != 0 {
			num := cPrimeFFT[j]*complex(real(gj), -imag(gj)) - xPrimeFFT[j]*complex(real(fj), -imag(fj))
			tau0FFT[j] = complex(real(num)/b0NormSq, imag(num)/b0NormSq)
		}
	}
	z0 := roundFFTToInt32s(tau0FFT, n)
	z0FFT := int32sToFFT(z0, n)

	// Lattice vector v = z0*b0 + z1*b1.
	// v1_j = z0_j*g_j + z1_j*G_j
	// v2_j = -z0_j*f_j - z1_j*F_j
	//
	// Coset signature (c,0) - v:
	//   first  component: c - v1 = c - z0*g - z1*G  (this is s2 in FN-DSA convention)
	//   second component: 0 - v2 = z0*f + z1*F       (this is s1 in FN-DSA convention)
	//
	// FN-DSA convention: s1*h + s2 = c, so s1 = z0*f + z1*F, s2 = c - z0*g - z1*G.
	s1FFT := make([]complex128, n) // z0*f + z1*F  (the part multiplied by h in verification)
	s2FFT := make([]complex128, n) // c - z0*g - z1*G  (the additive part)
	for j := range s1FFT {
		s1FFT[j] = z0FFT[j]*fFFT[j] + z1FFT[j]*FFFT[j]
		s2FFT[j] = cFFT[j] - z0FFT[j]*gFFT[j] - z1FFT[j]*GFFT[j]
	}

	s1Raw := roundFFTToInt32s(s1FFT, n)
	s2Raw := roundFFTToInt32s(s2FFT, n)

	s1 = make([]int32, n)
	s2 = make([]int32, n)
	for i := range s1 {
		s1[i] = centerModQ(s1Raw[i])
		s2[i] = centerModQ(s2Raw[i])
	}
	return s1, s2
}

// normSq computes the squared Euclidean norm of two integer slices.
func normSq(s1, s2 []int32) int64 {
	var n int64
	for _, v := range s1 {
		n += int64(v) * int64(v)
	}
	for _, v := range s2 {
		n += int64(v) * int64(v)
	}
	return n
}

// SignInternal signs msg using the secret key sk under parameter set p.
// It generates a random 40-byte salt, hashes salt||msg to a target polynomial,
// runs Babai nearest-plane sampling, and retries until the norm bound is met.
func SignInternal(sk, msg []byte, p *Params, rng io.Reader) ([]byte, error) {
	f, g, F, ok := DecodeSK(sk, p)
	if !ok {
		return nil, errors.New("fndsa: invalid secret key")
	}
	n := p.N

	// Recover G from (f, g, F) via the NTRU equation.
	G := recoverG(f, g, F, n)

	// Pre-compute h = g*f^{-1} mod q (needed for verification check).
	h := NTRUPublicKey(f, g, p)

	salt := make([]byte, 40)
	const maxAttempts = 1000
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Sample fresh salt each attempt.
		if _, err := io.ReadFull(rng, salt); err != nil {
			return nil, err
		}

		// Compute target c = HashToPoint(salt || msg).
		hashInput := make([]byte, 40+len(msg))
		copy(hashInput, salt)
		copy(hashInput[40:], msg)
		c := HashToPoint(hashInput, p)

		// Center c in (-Q/2, Q/2] for FFT arithmetic.
		cCentered := make([]int32, n)
		for i, v := range c {
			cCentered[i] = centerModQ(v)
		}

		// Run Babai nearest-plane to get (s1, s2).
		s1, s2 := ffSamplingBabai(cCentered, f, g, F, G, n)

		// Verify that s1*h + s2 ≡ c (mod q) — the FN-DSA verification equation.
		s1ModQ := make([]int32, n)
		for i, v := range s1 {
			s1ModQ[i] = ((v % Q) + Q) % Q
		}
		s1h := PolyMulNTT(s1ModQ, h, n)
		valid := true
		for i := range c {
			sum := ((int32(int64(s1h[i])+int64(s2[i]))%Q)+Q) % Q
			if sum != c[i] {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}

		// Check norm bound.
		ns := normSq(s1, s2)
		if ns > int64(p.BetaSq) {
			continue
		}

		// Encode signature.
		sig, encOk := EncodeSig(salt, s1, p)
		if !encOk {
			// Compressed s1 too large for format; retry with new salt.
			continue
		}
		return sig, nil
	}

	return nil, errors.New("fndsa: signing failed: could not produce valid signature in time")
}
