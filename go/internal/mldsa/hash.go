package mldsa

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// H computes SHAKE-256 hash with the given output length.
func H(data []byte, outLen int) []byte {
	h := sha3.NewShake256()
	h.Write(data)
	out := make([]byte, outLen)
	h.Read(out)
	return out
}

// ExpandA generates the k x l matrix A from seed rho using SHAKE-128.
// FIPS 204 Algorithm 32 (ExpandA) / Algorithm 30 (RejNTTPoly).
func ExpandA(rho []byte, k, l int) [][]([256]int) {
	A := make([][]([256]int), k)
	for i := 0; i < k; i++ {
		A[i] = make([][256]int, l)
		for j := 0; j < l; j++ {
			A[i][j] = rejNTTPoly(rho, byte(j), byte(i))
		}
	}
	return A
}

// rejNTTPoly generates a single polynomial via rejection sampling from SHAKE-128.
// FIPS 204 Algorithm 30.
func rejNTTPoly(rho []byte, j, i byte) [256]int {
	// Domain separator: rho || IntegerToBytes(s, 2) where s = 256*i + j
	// Per FIPS 204, the two bytes are j then i (little-endian of 256*i+j).
	seed := make([]byte, len(rho)+2)
	copy(seed, rho)
	seed[len(rho)] = j
	seed[len(rho)+1] = i

	h := sha3.NewShake128()
	h.Write(seed)

	var poly [256]int
	idx := 0
	buf := make([]byte, 3)
	for idx < 256 {
		h.Read(buf)
		// CoeffFromThreeBytes
		b0 := int(buf[0])
		b1 := int(buf[1])
		b2 := int(buf[2])
		val := b0 | (b1 << 8) | (b2 << 16)
		val &= 0x7FFFFF // mask to 23 bits
		if val < Q {
			poly[idx] = val
			idx++
		}
	}
	return poly
}

// ExpandS generates vectors s1 (length l) and s2 (length k) with coefficients
// in [-eta, eta] from seed sigma.
// FIPS 204 Algorithm 33 (ExpandS) / Algorithm 31 (RejBoundedPoly).
func ExpandS(sigma []byte, eta, k, l int) ([][256]int, [][256]int) {
	s1 := make([][256]int, l)
	s2 := make([][256]int, k)
	for r := 0; r < l; r++ {
		s1[r] = rejBoundedPoly(sigma, eta, uint16(r))
	}
	for r := 0; r < k; r++ {
		s2[r] = rejBoundedPoly(sigma, eta, uint16(l+r))
	}
	return s1, s2
}

// rejBoundedPoly samples a polynomial with coefficients in [-eta, eta].
// FIPS 204 Algorithm 31.
func rejBoundedPoly(sigma []byte, eta int, nonce uint16) [256]int {
	seed := make([]byte, len(sigma)+2)
	copy(seed, sigma)
	binary.LittleEndian.PutUint16(seed[len(sigma):], nonce)

	h := sha3.NewShake256()
	h.Write(seed)

	var poly [256]int
	idx := 0
	buf := make([]byte, 1)
	for idx < 256 {
		h.Read(buf)
		z := int(buf[0])
		z0 := z & 0x0F
		z1 := z >> 4

		if eta == 2 {
			if z0 < 15 {
				val := z0 - (z0*205>>10)*5 // z0 mod 5
				poly[idx] = ModQ(int64(eta - val))
				idx++
			}
			if idx < 256 && z1 < 15 {
				val := z1 - (z1*205>>10)*5 // z1 mod 5
				poly[idx] = ModQ(int64(eta - val))
				idx++
			}
		} else if eta == 4 {
			if z0 < 9 {
				poly[idx] = ModQ(int64(eta - z0))
				idx++
			}
			if idx < 256 && z1 < 9 {
				poly[idx] = ModQ(int64(eta - z1))
				idx++
			}
		}
	}
	return poly
}

// ExpandMask generates a vector y of l polynomials with coefficients in
// [-(gamma1-1), gamma1].
// FIPS 204 Algorithm 34 (ExpandMask).
func ExpandMask(rhoPrime []byte, gamma1, l, kappa int) [][256]int {
	y := make([][256]int, l)
	for r := 0; r < l; r++ {
		nonce := uint16(kappa + r)
		seed := make([]byte, len(rhoPrime)+2)
		copy(seed, rhoPrime)
		binary.LittleEndian.PutUint16(seed[len(rhoPrime):], nonce)

		h := sha3.NewShake256()
		h.Write(seed)

		var bitLen int
		if gamma1 == (1 << 17) {
			bitLen = 18
		} else {
			bitLen = 20
		}
		byteCount := 256 * bitLen / 8
		buf := make([]byte, byteCount)
		h.Read(buf)

		y[r] = bitUnpackGamma1(buf, gamma1, bitLen)
	}
	return y
}

// bitUnpackGamma1 unpacks bytes into polynomial coefficients in [-(gamma1-1), gamma1].
func bitUnpackGamma1(buf []byte, gamma1, bitLen int) [256]int {
	var poly [256]int
	if bitLen == 18 {
		// 18 bits per coefficient, 4 coefficients per 9 bytes
		for i := 0; i < 64; i++ {
			b := buf[9*i : 9*i+9]
			vals := [4]int{
				int(b[0]) | int(b[1])<<8 | (int(b[2])&0x03)<<16,
				int(b[2])>>2 | int(b[3])<<6 | (int(b[4])&0x0F)<<14,
				int(b[4])>>4 | int(b[5])<<4 | (int(b[6])&0x3F)<<12,
				int(b[6])>>6 | int(b[7])<<2 | int(b[8])<<10,
			}
			for j := 0; j < 4; j++ {
				vals[j] &= (1 << 18) - 1
				poly[4*i+j] = ModQ(int64(gamma1 - vals[j]))
			}
		}
	} else {
		// 20 bits per coefficient, 4 coefficients per 10 bytes
		for i := 0; i < 64; i++ {
			b := buf[10*i : 10*i+10]
			vals := [4]int{
				int(b[0]) | int(b[1])<<8 | (int(b[2])&0x0F)<<16,
				int(b[2])>>4 | int(b[3])<<4 | (int(b[4])&0xFF)<<12,
				int(b[5]) | int(b[6])<<8 | (int(b[7])&0x0F)<<16,
				int(b[7])>>4 | int(b[8])<<4 | int(b[9])<<12,
			}
			for j := 0; j < 4; j++ {
				vals[j] &= (1 << 20) - 1
				poly[4*i+j] = ModQ(int64(gamma1 - vals[j]))
			}
		}
	}
	return poly
}

// SampleInBall generates the challenge polynomial c with exactly tau nonzero
// coefficients, each +/- 1, using Fisher-Yates shuffle.
// FIPS 204 Algorithm 29.
func SampleInBall(cTilde []byte, tau int) [256]int {
	var c [256]int

	h := sha3.NewShake256()
	h.Write(cTilde)

	// Read 8 bytes for sign bits
	signBytes := make([]byte, 8)
	h.Read(signBytes)
	signs := binary.LittleEndian.Uint64(signBytes)

	buf := make([]byte, 1)
	for i := 256 - tau; i < 256; i++ {
		// Sample j uniformly from [0, i]
		for {
			h.Read(buf)
			j := int(buf[0])
			if j <= i {
				c[i] = c[j]
				if signs&1 == 0 {
					c[j] = 1
				} else {
					c[j] = ModQ(int64(-1)) // Q - 1
				}
				signs >>= 1
				break
			}
		}
	}
	return c
}
