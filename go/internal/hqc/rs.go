package hqc

// Reed-Solomon encoding and decoding over GF(2^8) for HQC.
//
// RS(n1, k) with minimum distance d = n1 - k + 1 = 2*delta + 1.
// The generator polynomial g(x) = prod(x - alpha^i) for i = 1..2*delta.
// alpha is the primitive element of GF(2^8) (alpha = gfGen = 3, using polynomial 0x11B).

// rsGeneratorPoly computes the generator polynomial of the RS code.
// Returns coefficients [g0, g1, ..., g_{2*delta}] where g_{2*delta} = 1.
func rsGeneratorPoly(delta int) []byte {
	deg := 2 * delta
	g := make([]byte, deg+1)
	g[0] = 1 // g(x) = 1

	// Multiply by (x - alpha^i) for i = 1..2*delta
	for i := 1; i <= deg; i++ {
		alphai := gf256Pow(gfGen, i) // alpha^i
		// Multiply g by (x - alpha^i) = (x + alpha^i) in GF(2^8)
		// New coefficient: g[j] = g[j-1] + alpha^i * g[j]
		prev := byte(0)
		for j := 0; j <= deg; j++ {
			tmp := g[j]
			g[j] = gf256Mul(g[j], alphai) ^ prev
			prev = tmp
		}
	}

	return g
}

// rsEncode performs systematic RS encoding.
// Input: msg of length k bytes.
// Output: codeword of length n1 bytes (parity || msg).
func rsEncode(msg []byte, p *Params) []byte {
	k := p.K
	n1 := p.N1
	delta := p.Delta
	g := rsGeneratorPoly(delta)
	parityLen := 2 * delta // n1 - k

	// Linear feedback shift register encoding
	// Process message bytes from high to low degree
	feedback := make([]byte, parityLen)

	for i := k - 1; i >= 0; i-- {
		coeff := gf256Add(msg[i], feedback[parityLen-1])
		for j := parityLen - 1; j > 0; j-- {
			feedback[j] = gf256Add(feedback[j-1], gf256Mul(coeff, g[j]))
		}
		feedback[0] = gf256Mul(coeff, g[0])
	}

	// Codeword = [parity bytes] [message bytes]
	codeword := make([]byte, n1)
	copy(codeword, feedback[:parityLen])
	copy(codeword[parityLen:], msg)

	return codeword
}

// rsDecode decodes a received RS codeword.
// Returns the decoded message (k bytes) and true if successful,
// or nil and false if too many errors.
func rsDecode(received []byte, p *Params) ([]byte, bool) {
	n1 := p.N1
	k := p.K
	delta := p.Delta

	// Make a working copy
	r := make([]byte, n1)
	copy(r, received)

	// Step 1: Compute syndromes S[1..2*delta]
	syndromes := make([]byte, 2*delta+1) // syndromes[0] unused
	allZero := true
	for i := 1; i <= 2*delta; i++ {
		alphai := gf256Pow(gfGen, i)
		s := byte(0)
		for j := n1 - 1; j >= 0; j-- {
			s = gf256Add(gf256Mul(s, alphai), r[j])
		}
		syndromes[i] = s
		if s != 0 {
			allZero = false
		}
	}

	if allZero {
		// No errors
		msg := make([]byte, k)
		copy(msg, r[2*delta:])
		return msg, true
	}

	// Step 2: Berlekamp-Massey algorithm to find error locator polynomial sigma
	sigma := berlekampMassey(syndromes, delta)
	sigDeg := 0
	for i := delta; i >= 0; i-- {
		if sigma[i] != 0 {
			sigDeg = i
			break
		}
	}
	if sigDeg > delta {
		return nil, false
	}

	// Step 3: Find roots of sigma (Chien search)
	errorPositions := make([]int, 0, sigDeg)
	for i := 0; i < n1; i++ {
		// Evaluate sigma(alpha^(-i)) = sigma(alpha^(255-i))
		alphaInv := gf256Pow(gfGen, 255-i)
		val := byte(0)
		alphaPow := byte(1)
		for j := 0; j <= sigDeg; j++ {
			val ^= gf256Mul(sigma[j], alphaPow)
			alphaPow = gf256Mul(alphaPow, alphaInv)
		}
		if val == 0 {
			errorPositions = append(errorPositions, i)
		}
	}

	if len(errorPositions) != sigDeg {
		return nil, false // Number of roots doesn't match degree
	}

	// Step 4: Forney's algorithm - compute error values
	// omega(x) = S(x) * sigma(x) mod x^(2*delta+1)
	omega := make([]byte, 2*delta+1)
	for i := 0; i < 2*delta; i++ {
		for j := 0; j <= sigDeg && j <= i; j++ {
			omega[i+1] ^= gf256Mul(sigma[j], syndromes[i+1-j])
		}
	}

	// sigma'(x) = formal derivative of sigma
	sigmaPrime := make([]byte, delta+1)
	for i := 1; i <= sigDeg; i += 2 {
		// In GF(2), derivative of x^i = i*x^(i-1); odd powers survive
		sigmaPrime[i-1] = sigma[i]
	}

	// Correct errors
	for _, pos := range errorPositions {
		alphaInvI := gf256Inv(gf256Pow(gfGen, pos))

		// Evaluate omega(alpha^(-pos))
		omegaVal := byte(0)
		alphaPow := byte(1)
		for j := 0; j <= 2*delta; j++ {
			omegaVal ^= gf256Mul(omega[j], alphaPow)
			alphaPow = gf256Mul(alphaPow, alphaInvI)
		}

		// Evaluate sigma'(alpha^(-pos))
		sigPrimeVal := byte(0)
		alphaPow = byte(1)
		for j := 0; j < len(sigmaPrime); j++ {
			sigPrimeVal ^= gf256Mul(sigmaPrime[j], alphaPow)
			alphaPow = gf256Mul(alphaPow, alphaInvI)
		}

		if sigPrimeVal == 0 {
			return nil, false
		}

		errorVal := gf256Mul(omegaVal, gf256Inv(sigPrimeVal))
		r[pos] ^= errorVal
	}

	// Extract message
	msg := make([]byte, k)
	copy(msg, r[2*delta:])
	return msg, true
}

// berlekampMassey implements the Berlekamp-Massey algorithm.
// Returns the error locator polynomial sigma with coefficients sigma[0..delta].
func berlekampMassey(syndromes []byte, delta int) []byte {
	n := 2 * delta
	sigma := make([]byte, delta+2)
	sigma[0] = 1
	b := make([]byte, delta+2)
	b[0] = 1
	L := 0
	m := 1
	deltaN := byte(1) // previous discrepancy

	for k := 1; k <= n; k++ {
		// Compute discrepancy d
		d := syndromes[k]
		for i := 1; i <= L; i++ {
			d ^= gf256Mul(sigma[i], syndromes[k-i])
		}

		if d == 0 {
			m++
			continue
		}

		// t(x) = sigma(x) - (d/deltaN) * x^m * b(x)
		t := make([]byte, delta+2)
		copy(t, sigma)
		coeff := gf256Mul(d, gf256Inv(deltaN))
		for i := 0; i <= delta+1-m; i++ {
			if i+m <= delta+1 {
				t[i+m] ^= gf256Mul(coeff, b[i])
			}
		}

		if 2*L < k {
			// b = sigma, update L
			copy(b, sigma)
			L = k - L
			deltaN = d
			m = 1
		} else {
			m++
		}
		copy(sigma, t)
	}

	return sigma[:delta+1]
}
