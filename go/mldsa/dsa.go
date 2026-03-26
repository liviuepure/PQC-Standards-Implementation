// Package mldsa implements ML-DSA (FIPS 204) digital signatures.
package mldsa

import (
	"crypto/rand"

	"github.com/baron-chain/PQC-Standards-Implementation/go/internal/mldsa"
)

// Params is the ML-DSA parameter set.
type Params = mldsa.Params

// Pre-defined parameter sets.
var (
	MLDSA44 = mldsa.MLDSA44
	MLDSA65 = mldsa.MLDSA65
	MLDSA87 = mldsa.MLDSA87
)

// KeyGen generates an ML-DSA key pair.
// Returns (publicKey, secretKey).
func KeyGen(params *Params) (pk, sk []byte) {
	xi := make([]byte, 32)
	if _, err := rand.Read(xi); err != nil {
		panic("mldsa: failed to read random bytes")
	}
	return KeyGenInternal(params, xi)
}

// KeyGenInternal is deterministic key generation from seed xi.
func KeyGenInternal(params *Params, xi []byte) (pk, sk []byte) {
	k := params.K
	l := params.L
	eta := params.Eta

	// (rho, rhoPrime, K) = SHAKE-256(xi || k || l, 128)
	// Per FIPS 204: H(xi, 128) where xi is 32 bytes
	seed := make([]byte, 34)
	copy(seed, xi)
	seed[32] = byte(k)
	seed[33] = byte(l)
	expanded := mldsa.H(seed, 128)
	rho := expanded[:32]
	rhoPrime := expanded[32:96]
	K := expanded[96:128]

	// A = ExpandA(rho)
	Ahat := mldsa.ExpandA(rho, k, l)

	// (s1, s2) = ExpandS(rhoPrime, eta)
	s1, s2 := mldsa.ExpandS(rhoPrime, eta, k, l)

	// t = NTT^-1(A_hat * NTT(s1)) + s2
	s1Hat := make([][256]int, l)
	for i := 0; i < l; i++ {
		var tmp [256]int
		copy(tmp[:], s1[i][:])
		mldsa.NTT(&tmp)
		s1Hat[i] = tmp
	}

	t := make([][256]int, k)
	for i := 0; i < k; i++ {
		var acc [256]int
		for j := 0; j < l; j++ {
			prod := mldsa.PointwiseMul(Ahat[i][j], s1Hat[j])
			for c := 0; c < 256; c++ {
				acc[c] = mldsa.FieldAdd(acc[c], prod[c])
			}
		}
		mldsa.NTTInverse(&acc)
		for c := 0; c < 256; c++ {
			t[i][c] = mldsa.FieldAdd(acc[c], s2[i][c])
		}
	}

	// (t1, t0) = Power2Round(t)
	t1 := make([][256]int, k)
	t0 := make([][256]int, k)
	for i := 0; i < k; i++ {
		for j := 0; j < 256; j++ {
			t1[i][j], t0[i][j] = mldsa.Power2Round(t[i][j])
		}
	}

	// pk = EncodePK(rho, t1)
	pk = mldsa.EncodePK(rho, t1)

	// tr = H(pk, 64)
	tr := mldsa.H(pk, 64)

	// sk = EncodeSK(rho, K, tr, s1, s2, t0)
	sk = mldsa.EncodeSK(rho, K, tr, s1, s2, t0, eta)

	return pk, sk
}

// Sign produces an ML-DSA signature on msg using secret key sk.
func Sign(sk, msg []byte, params *Params) []byte {
	rnd := make([]byte, 32)
	if _, err := rand.Read(rnd); err != nil {
		panic("mldsa: failed to read random bytes")
	}
	return SignInternal(sk, msg, rnd, params)
}

// SignInternal is the deterministic signing function.
func SignInternal(sk, msg, rnd []byte, params *Params) []byte {
	k := params.K
	l := params.L
	gamma1 := params.Gamma1
	gamma2 := params.Gamma2
	beta := params.Beta
	tau := params.Tau
	omega := params.Omega
	lambda := params.Lambda

	// Decode sk
	rho, K, tr, s1, s2, t0 := mldsa.DecodeSK(sk, params)

	// Compute NTT forms of s1, s2, t0
	s1Hat := make([][256]int, l)
	for i := 0; i < l; i++ {
		var tmp [256]int
		copy(tmp[:], s1[i][:])
		mldsa.NTT(&tmp)
		s1Hat[i] = tmp
	}
	s2Hat := make([][256]int, k)
	for i := 0; i < k; i++ {
		var tmp [256]int
		copy(tmp[:], s2[i][:])
		mldsa.NTT(&tmp)
		s2Hat[i] = tmp
	}
	t0Hat := make([][256]int, k)
	for i := 0; i < k; i++ {
		var tmp [256]int
		copy(tmp[:], t0[i][:])
		mldsa.NTT(&tmp)
		t0Hat[i] = tmp
	}

	// A_hat = ExpandA(rho)
	Ahat := mldsa.ExpandA(rho, k, l)

	// mu = H(tr || msg, 64)
	muInput := make([]byte, len(tr)+len(msg))
	copy(muInput, tr)
	copy(muInput[len(tr):], msg)
	mu := mldsa.H(muInput, 64)

	// rhoPrime = H(K || rnd || mu, 64)
	rpInput := make([]byte, 32+32+64)
	copy(rpInput, K)
	copy(rpInput[32:], rnd)
	copy(rpInput[64:], mu)
	rhoPrime := mldsa.H(rpInput, 64)

	kappa := 0
	for {
		// y = ExpandMask(rhoPrime, kappa)
		y := mldsa.ExpandMask(rhoPrime, gamma1, l, kappa*l)

		// w = NTT^-1(A_hat * NTT(y))
		yHat := make([][256]int, l)
		for i := 0; i < l; i++ {
			var tmp [256]int
			copy(tmp[:], y[i][:])
			mldsa.NTT(&tmp)
			yHat[i] = tmp
		}

		w := make([][256]int, k)
		for i := 0; i < k; i++ {
			var acc [256]int
			for j := 0; j < l; j++ {
				prod := mldsa.PointwiseMul(Ahat[i][j], yHat[j])
				for c := 0; c < 256; c++ {
					acc[c] = mldsa.FieldAdd(acc[c], prod[c])
				}
			}
			mldsa.NTTInverse(&acc)
			w[i] = acc
		}

		// w1 = HighBits(w)
		w1 := make([][256]int, k)
		for i := 0; i < k; i++ {
			for j := 0; j < 256; j++ {
				w1[i][j] = mldsa.HighBits(w[i][j], 2*gamma2)
			}
		}

		// cTilde = H(mu || EncodeW1(w1), 2*lambda)
		w1Enc := mldsa.EncodeW1(w1, gamma2)
		cInput := make([]byte, len(mu)+len(w1Enc))
		copy(cInput, mu)
		copy(cInput[len(mu):], w1Enc)
		cTilde := mldsa.H(cInput, 2*lambda)

		// c = SampleInBall(cTilde, tau)
		cPoly := mldsa.SampleInBall(cTilde, tau)

		// c_hat = NTT(c)
		var cHat [256]int
		copy(cHat[:], cPoly[:])
		mldsa.NTT(&cHat)

		// z = y + NTT^-1(c_hat * s1_hat)
		z := make([][256]int, l)
		for i := 0; i < l; i++ {
			cs1 := mldsa.PointwiseMul(cHat, s1Hat[i])
			mldsa.NTTInverse(&cs1)
			for j := 0; j < 256; j++ {
				z[i][j] = mldsa.FieldAdd(y[i][j], cs1[j])
			}
		}

		// Check ||z||_inf < gamma1 - beta
		if !checkNormBound(z, l, gamma1-beta) {
			kappa++
			continue
		}

		// r0 = LowBits(w - cs2)
		// cs2 = NTT^-1(c_hat * s2_hat)
		cs2 := make([][256]int, k)
		for i := 0; i < k; i++ {
			tmp := mldsa.PointwiseMul(cHat, s2Hat[i])
			mldsa.NTTInverse(&tmp)
			cs2[i] = tmp
		}

		wMinusCs2 := make([][256]int, k)
		for i := 0; i < k; i++ {
			for j := 0; j < 256; j++ {
				wMinusCs2[i][j] = mldsa.FieldSub(w[i][j], cs2[i][j])
			}
		}

		r0 := make([][256]int, k)
		for i := 0; i < k; i++ {
			for j := 0; j < 256; j++ {
				r0[i][j] = mldsa.LowBits(wMinusCs2[i][j], 2*gamma2)
			}
		}

		if !checkNormBound(r0, k, gamma2-beta) {
			kappa++
			continue
		}

		// ct0 = NTT^-1(c_hat * t0_hat)
		ct0 := make([][256]int, k)
		for i := 0; i < k; i++ {
			tmp := mldsa.PointwiseMul(cHat, t0Hat[i])
			mldsa.NTTInverse(&tmp)
			ct0[i] = tmp
		}

		if !checkNormBound(ct0, k, gamma2) {
			kappa++
			continue
		}

		// Compute hints
		hints := make([][256]int, k)
		hintCount := 0
		for i := 0; i < k; i++ {
			for j := 0; j < 256; j++ {
				val := mldsa.FieldAdd(wMinusCs2[i][j], ct0[i][j])
				h := mldsa.HighBits(val, 2*gamma2)
				h2 := mldsa.HighBits(wMinusCs2[i][j], 2*gamma2)
				if h != h2 {
					hints[i][j] = 1
					hintCount++
				}
			}
		}

		if hintCount > omega {
			kappa++
			continue
		}

		return mldsa.EncodeSig(cTilde, z, hints, params)
	}
}

// Verify verifies an ML-DSA signature on msg using public key pk.
func Verify(pk, msg, sig []byte, params *Params) bool {
	k := params.K
	l := params.L
	gamma1 := params.Gamma1
	gamma2 := params.Gamma2
	beta := params.Beta
	tau := params.Tau
	omega := params.Omega
	lambda := params.Lambda

	if len(sig) != params.SigSize {
		return false
	}

	// Decode pk
	rho, t1 := mldsa.DecodePK(pk, k)

	// Decode sig
	cTilde, z, h, ok := mldsa.DecodeSig(sig, params)
	if !ok {
		return false
	}

	// Check hint count
	hintCount := 0
	for i := 0; i < k; i++ {
		for j := 0; j < 256; j++ {
			hintCount += h[i][j]
		}
	}
	if hintCount > omega {
		return false
	}

	// Check ||z||_inf < gamma1 - beta
	if !checkNormBound(z, l, gamma1-beta) {
		return false
	}

	// A_hat = ExpandA(rho)
	Ahat := mldsa.ExpandA(rho, k, l)

	// tr = H(pk, 64)
	tr := mldsa.H(pk, 64)

	// mu = H(tr || msg, 64)
	muInput := make([]byte, len(tr)+len(msg))
	copy(muInput, tr)
	copy(muInput[len(tr):], msg)
	mu := mldsa.H(muInput, 64)

	// c = SampleInBall(cTilde, tau)
	cPoly := mldsa.SampleInBall(cTilde, tau)
	var cHat [256]int
	copy(cHat[:], cPoly[:])
	mldsa.NTT(&cHat)

	// w'_approx = NTT^-1(A_hat * NTT(z)) - NTT^-1(c_hat * NTT(t1 * 2^d))
	zHat := make([][256]int, l)
	for i := 0; i < l; i++ {
		var tmp [256]int
		copy(tmp[:], z[i][:])
		mldsa.NTT(&tmp)
		zHat[i] = tmp
	}

	t1Hat := make([][256]int, k)
	for i := 0; i < k; i++ {
		var tmp [256]int
		for j := 0; j < 256; j++ {
			tmp[j] = mldsa.FieldMul(t1[i][j], 1<<params.D)
		}
		mldsa.NTT(&tmp)
		t1Hat[i] = tmp
	}

	wApprox := make([][256]int, k)
	for i := 0; i < k; i++ {
		// A_hat * z_hat
		var az [256]int
		for j := 0; j < l; j++ {
			prod := mldsa.PointwiseMul(Ahat[i][j], zHat[j])
			for c := 0; c < 256; c++ {
				az[c] = mldsa.FieldAdd(az[c], prod[c])
			}
		}

		// c_hat * t1_hat_scaled
		ct1 := mldsa.PointwiseMul(cHat, t1Hat[i])

		// w'_approx = NTT^-1(A*z - c*t1*2^d)
		for c := 0; c < 256; c++ {
			az[c] = mldsa.FieldSub(az[c], ct1[c])
		}
		mldsa.NTTInverse(&az)
		wApprox[i] = az
	}

	// w1' = UseHint(h, w'_approx)
	w1Prime := make([][256]int, k)
	for i := 0; i < k; i++ {
		for j := 0; j < 256; j++ {
			w1Prime[i][j] = mldsa.UseHint(h[i][j], wApprox[i][j], 2*gamma2)
		}
	}

	// cTilde' = H(mu || EncodeW1(w1'))
	w1Enc := mldsa.EncodeW1(w1Prime, gamma2)
	cInput := make([]byte, len(mu)+len(w1Enc))
	copy(cInput, mu)
	copy(cInput[len(mu):], w1Enc)
	cTildeCheck := mldsa.H(cInput, 2*lambda)

	// Compare
	if len(cTilde) != len(cTildeCheck) {
		return false
	}
	for i := range cTilde {
		if cTilde[i] != cTildeCheck[i] {
			return false
		}
	}
	return true
}

// checkNormBound checks that all coefficients of the vector have
// |coeff| < bound (using centered representatives).
func checkNormBound(v [][256]int, n, bound int) bool {
	for i := 0; i < n; i++ {
		for j := 0; j < 256; j++ {
			val := v[i][j]
			// Convert to centered representation
			if val > mldsa.Q/2 {
				val = mldsa.Q - val
			}
			if val >= bound {
				return false
			}
		}
	}
	return true
}
