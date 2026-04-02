package hqc

import (
	"encoding/binary"
)

// GF(2) polynomial arithmetic: polynomials over GF(2) packed into []uint64 words.
// Each polynomial has at most n bits. Arithmetic is in GF(2)[x]/(x^n - 1).

// vectAdd computes out = a XOR b (polynomial addition in GF(2)).
// a and b must have the same length.
func vectAdd(a, b []uint64) []uint64 {
	n := len(a)
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// vectAddInPlace computes a ^= b in-place.
func vectAddInPlace(a, b []uint64) {
	for i := range b {
		a[i] ^= b[i]
	}
}

// vectSetBit sets bit at position pos in the vector v.
func vectSetBit(v []uint64, pos int) {
	v[pos/64] |= 1 << uint(pos%64)
}

// vectGetBit returns the bit at position pos in the vector v.
func vectGetBit(v []uint64, pos int) uint64 {
	return (v[pos/64] >> uint(pos%64)) & 1
}

// vectWeight returns the Hamming weight of a GF(2) vector.
func vectWeight(v []uint64) int {
	w := 0
	for _, word := range v {
		w += popcount64(word)
	}
	return w
}

// popcount64 returns the number of set bits in x.
func popcount64(x uint64) int {
	// Kernighan's bit counting
	count := 0
	for x != 0 {
		x &= x - 1
		count++
	}
	return count
}

// vectToBytes converts a uint64 vector to bytes (little-endian).
func vectToBytes(v []uint64, nBytes int) []byte {
	out := make([]byte, nBytes)
	for i := 0; i < len(v) && i*8 < nBytes; i++ {
		remaining := nBytes - i*8
		if remaining >= 8 {
			binary.LittleEndian.PutUint64(out[i*8:], v[i])
		} else {
			var buf [8]byte
			binary.LittleEndian.PutUint64(buf[:], v[i])
			copy(out[i*8:], buf[:remaining])
		}
	}
	return out
}

// vectFromBytes converts bytes to a uint64 vector (little-endian).
func vectFromBytes(data []byte, nWords int) []uint64 {
	v := make([]uint64, nWords)
	for i := 0; i < nWords; i++ {
		start := i * 8
		if start >= len(data) {
			break
		}
		end := start + 8
		if end > len(data) {
			// Partial last word
			var buf [8]byte
			copy(buf[:], data[start:])
			v[i] = binary.LittleEndian.Uint64(buf[:])
		} else {
			v[i] = binary.LittleEndian.Uint64(data[start:end])
		}
	}
	return v
}

// vectResize returns a copy of v truncated/masked to exactly nBits bits.
func vectResize(v []uint64, nBits int) []uint64 {
	nWords := (nBits + 63) / 64
	out := make([]uint64, nWords)
	copy(out, v)
	// Mask the last word
	rem := nBits % 64
	if rem != 0 && nWords > 0 {
		out[nWords-1] &= (1 << uint(rem)) - 1
	}
	return out
}

// vectEqual returns 1 if a == b (constant-time), 0 otherwise.
func vectEqual(a, b []uint64) int {
	var diff uint64
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		diff |= a[i] ^ b[i]
	}
	// Check remaining words in a
	for i := n; i < len(a); i++ {
		diff |= a[i]
	}
	// Check remaining words in b
	for i := n; i < len(b); i++ {
		diff |= b[i]
	}
	// Return 1 if diff == 0
	d := diff | (diff >> 32)
	d |= d >> 16
	d |= d >> 8
	d |= d >> 4
	d |= d >> 2
	d |= d >> 1
	return 1 - int(d&1)
}

// baseMul performs carryless multiplication of two 64-bit words.
// Returns (lo, hi) such that a * b = hi<<64 | lo in GF(2).
func baseMul(a, b uint64) (uint64, uint64) {
	var lo, hi uint64

	// Process each bit of a
	for i := 0; i < 64; i++ {
		if (a>>uint(i))&1 == 0 {
			continue
		}
		// Add b shifted left by i bits
		if i == 0 {
			lo ^= b
		} else {
			lo ^= b << uint(i)
			hi ^= b >> uint(64-i)
		}
	}

	return lo, hi
}

// schoolbookMul performs polynomial multiplication of two GF(2) polynomials
// stored as []uint64 words. a has sizeA words, b has sizeB words.
// Result has sizeA+sizeB words.
func schoolbookMul(a []uint64, sizeA int, b []uint64, sizeB int) []uint64 {
	out := make([]uint64, sizeA+sizeB)
	for i := 0; i < sizeA; i++ {
		if a[i] == 0 {
			continue
		}
		for j := 0; j < sizeB; j++ {
			if b[j] == 0 {
				continue
			}
			lo, hi := baseMul(a[i], b[j])
			out[i+j] ^= lo
			out[i+j+1] ^= hi
		}
	}
	return out
}

// vectMul computes out = a * b mod (x^n - 1) in GF(2)[x].
func vectMul(a, b []uint64, n int) []uint64 {
	nWords := (n + 63) / 64

	// Pad a and b to nWords
	aPad := make([]uint64, nWords)
	bPad := make([]uint64, nWords)
	copy(aPad, a)
	copy(bPad, b)

	// Mask last word of both inputs
	rem := n % 64
	if rem != 0 {
		aPad[nWords-1] &= (1 << uint(rem)) - 1
		bPad[nWords-1] &= (1 << uint(rem)) - 1
	}

	// Full product
	prod := schoolbookMul(aPad, nWords, bPad, nWords)

	// Reduce mod (x^n - 1): add bits above position n back in
	out := make([]uint64, nWords)
	copy(out, prod[:nWords])

	// Bits from position n to 2*n-1 need to be XORed at positions 0 to n-1
	wordOff := n / 64

	if rem == 0 {
		// Aligned case
		for i := 0; i < nWords; i++ {
			if wordOff+i < 2*nWords {
				out[i] ^= prod[wordOff+i]
			}
		}
	} else {
		// Unaligned case: bits at position n start mid-word
		for i := 0; i < nWords; i++ {
			idx := wordOff + i
			if idx < 2*nWords {
				out[i] ^= prod[idx] >> uint(rem)
			}
			if idx+1 < 2*nWords {
				out[i] ^= prod[idx+1] << uint(64-rem)
			}
		}
	}

	// Mask the last word
	if rem != 0 {
		out[nWords-1] &= (1 << uint(rem)) - 1
	}

	return out
}

