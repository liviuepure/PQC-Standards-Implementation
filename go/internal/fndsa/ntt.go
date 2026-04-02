package fndsa

// NTT and INTT for FN-DSA (FIPS 206 / FALCON) mod q = 12289.
//
// The ring is Z[x]/(x^n + 1) with q = 12289 = 12 * 1024 + 1.
// The primitive root mod q is g = 11 (order q−1 = 12288 = 2^12 * 3).
// For a negacyclic NTT of size n, the twiddle factor is:
//   psi_n = 11^((q−1)/(2n)) mod q   — a primitive 2n-th root of unity.
//
// The butterfly structure follows Cooley–Tukey with bit-reversed twiddle ordering:
//   zeta_k = psi_n^(bit_rev(k, log2(n))) mod q
// NTT outputs in bit-reversed order; INTT undoes the butterflies in reverse.
//
// On-the-fly twiddle computation (O(n log n) multiplications, no table):
// Task 3 will replace this with precomputed tables for speed.

// nttMulModQ returns (a * b) mod Q.
func nttMulModQ(a, b int64) int32 {
	return int32(a * b % int64(Q))
}

// nttAddModQ returns (a + b) mod Q with inputs in [0, Q).
func nttAddModQ(a, b int32) int32 {
	r := a + b
	if r >= Q {
		r -= Q
	}
	return r
}

// nttSubModQ returns (a - b) mod Q with inputs in [0, Q).
func nttSubModQ(a, b int32) int32 {
	r := a - b
	if r < 0 {
		r += Q
	}
	return r
}

// nttPow returns base^exp mod Q using fast exponentiation.
func nttPow(base, exp int64) int32 {
	result := int64(1)
	b := base % int64(Q)
	if b < 0 {
		b += int64(Q)
	}
	for exp > 0 {
		if exp&1 == 1 {
			result = result * b % int64(Q)
		}
		exp >>= 1
		b = b * b % int64(Q)
	}
	return int32(result)
}

// nttBitRev reverses the low logn bits of k.
func nttBitRev(k, logn int) int {
	r := 0
	for i := 0; i < logn; i++ {
		r = (r << 1) | (k & 1)
		k >>= 1
	}
	return r
}

// nttPsi returns the primitive 2n-th root of unity mod Q for a given n.
// g = 11 is the primitive root mod Q = 12289 (order Q-1 = 12288 = 2^12 * 3).
// psi_n = 11^((Q-1)/(2n)) mod Q.
func nttPsi(n int) int64 {
	return int64(nttPow(11, int64((Q-1)/(2*n))))
}

// NTT performs an in-place forward negacyclic Number Theoretic Transform.
// It maps f ∈ Z_q[x]/(x^n+1) (coefficients in [0,Q)) to its NTT representation.
// n must be 512 or 1024.
//
// Butterfly: for group k (1-indexed), twiddle = psi^bit_rev(k, log2(n)).
// The output is in bit-reversed order (consistent with INTT).
// Twiddle factors are looked up from the precomputed zeta tables in tables.go.
func NTT(f []int32, n int) {
	var zetas []int32
	if n == 512 {
		zetas = nttZetas512[:]
	} else {
		zetas = nttZetas1024[:]
	}

	k := 0
	for length := n >> 1; length >= 1; length >>= 1 {
		for start := 0; start < n; start += 2 * length {
			k++
			zeta := int64(zetas[k])
			for j := start; j < start+length; j++ {
				t := nttMulModQ(zeta, int64(f[j+length]))
				f[j+length] = nttSubModQ(f[j], t)
				f[j] = nttAddModQ(f[j], t)
			}
		}
	}
}

// INTT performs an in-place inverse negacyclic Number Theoretic Transform.
// It is the inverse of NTT: INTT(NTT(f)) = f.
// n must be 512 or 1024.
//
// The butterfly order reverses NTT exactly: within each layer, blocks are
// processed in reverse order so the twiddle indices match their NTT counterparts.
// The result is scaled by n^{-1} mod Q.
// Inverse twiddle factors are looked up from the precomputed inverse zeta tables in tables.go.
func INTT(f []int32, n int) {
	var zetasInv []int32
	var nInv int64
	if n == 512 {
		zetasInv = nttZetasInv512[:]
		nInv = int64(nttPow(512, int64(Q-2)))
	} else {
		zetasInv = nttZetasInv1024[:]
		nInv = int64(nttPow(1024, int64(Q-2)))
	}

	k := n
	for length := 1; length < n; length <<= 1 {
		// Iterate starts in reverse order to undo NTT butterflies in reverse.
		for start := n - 2*length; start >= 0; start -= 2 * length {
			k--
			zetaInv := int64(zetasInv[k])
			for j := start; j < start+length; j++ {
				t := f[j]
				f[j] = nttAddModQ(t, f[j+length])
				f[j+length] = nttMulModQ(zetaInv, int64(nttSubModQ(t, f[j+length])))
			}
		}
	}

	// Scale by n^{-1} mod Q.
	for i := range f {
		f[i] = nttMulModQ(nInv, int64(f[i]))
	}
}
