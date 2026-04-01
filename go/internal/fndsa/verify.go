package fndsa

// Verify implements FN-DSA verification (FIPS 206 Algorithm 4).
//
// Returns true iff sig is a valid FN-DSA signature on msg under public key pk
// for parameter set p.
func Verify(pk, msg, sig []byte, p *Params) bool {
	// 1. Decode and validate public key.
	h := DecodePK(pk, p)
	if h == nil {
		return false
	}

	// 2. Decode and validate signature.
	salt, s1, ok := DecodeSig(sig, p)
	if !ok {
		return false
	}

	// 3. Recompute c = HashToPoint(salt || msg).
	hashInput := make([]byte, 40+len(msg))
	copy(hashInput, salt)
	copy(hashInput[40:], msg)
	c := HashToPoint(hashInput, p)

	// 4. Compute s2 = c - s1·h (mod q), centered.
	//    PolyMulNTT requires inputs in [0, Q); reduce s1 mod Q first.
	n := p.N
	s1ModQ := make([]int32, n)
	for i, v := range s1 {
		s1ModQ[i] = ((v % Q) + Q) % Q
	}
	s1h := PolyMulNTT(s1ModQ, h, n)
	s2 := make([]int32, n)
	for i := range s2 {
		s2[i] = centerModQ(c[i] - s1h[i])
	}

	// 5. Norm check: ||(s1, s2)||² ≤ β².
	//    s1 coefficients from DecodeSig are centered (signed), so use directly.
	return normSq(s1, s2) <= int64(p.BetaSq)
}
