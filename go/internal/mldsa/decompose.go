package mldsa

// Power2Round decomposes r into (r1, r0) such that r = r1*2^d + r0,
// with r0 in (-2^(d-1), 2^(d-1)].
// FIPS 204 Algorithm 35.
func Power2Round(r int) (int, int) {
	rp := ModQ(int64(r))
	d := 13
	twoD := 1 << d // 8192
	r0 := centerMod(rp, twoD)
	r1 := (rp - r0) / twoD
	return r1, r0
}

// centerMod returns r mod alpha centered in (-alpha/2, alpha/2].
func centerMod(r, alpha int) int {
	r0 := r % alpha
	if r0 > alpha/2 {
		r0 -= alpha
	}
	return r0
}

// Decompose decomposes r into (r1, r0) such that r = r1*alpha + r0,
// with r0 in (-alpha/2, alpha/2] except for special corner case.
// FIPS 204 Algorithm 36.
func Decompose(r, alpha int) (int, int) {
	rp := ModQ(int64(r))
	r0 := centerMod(rp, alpha)
	if rp-r0 == Q-1 {
		return 0, r0 - 1
	}
	r1 := (rp - r0) / alpha
	return r1, r0
}

// HighBits returns the high-order representative of r.
// FIPS 204 Algorithm 37.
func HighBits(r, alpha int) int {
	r1, _ := Decompose(r, alpha)
	return r1
}

// LowBits returns the low-order representative of r.
// FIPS 204 Algorithm 38.
func LowBits(r, alpha int) int {
	_, r0 := Decompose(r, alpha)
	return r0
}

// MakeHint returns 1 if the high bits of r differ when z0 is added.
// FIPS 204 Algorithm 39.
func MakeHint(z0, r1, alpha int) int {
	// hint = 1 if HighBits(r) != HighBits(r - z0)
	// Rewritten per FIPS 204: MakeHint(-ct0, w-cs2+ct0)
	// Actually uses the formulation: hint if UseHint changes the value
	v := r1*alpha + z0
	h0 := HighBits(ModQ(int64(v)), alpha)
	h1 := HighBits(ModQ(int64(v-z0)), alpha) // this is HighBits(r1*alpha) which might not be r1 due to centering
	if h0 != h1 {
		return 1
	}
	return 0
}

// UseHint uses the hint to recover the correct high bits.
// FIPS 204 Algorithm 40.
func UseHint(h int, r, alpha int) int {
	m := (Q - 1) / alpha
	r1, r0 := Decompose(r, alpha)
	if h == 0 {
		return r1
	}
	if r0 > 0 {
		if r1+1 == m {
			return 0
		}
		return r1 + 1
	}
	if r1 == 0 {
		return m - 1
	}
	return r1 - 1
}
