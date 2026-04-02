package hqc

// Reed-Muller code RM(1, 7) for HQC.
//
// The first-order Reed-Muller code RM(1, 7) encodes 8 bits (1 byte)
// into 128 bits (16 bytes). The encoding uses the generator matrix
// of RM(1, 7), which consists of the all-ones word and the 7 rows
// of the Walsh-Hadamard basis vectors.
//
// For HQC, the RM codeword is then duplicated (Multiplicity times)
// to form an n2-bit codeword for additional error correction.

// rmBaseLen is the base Reed-Muller codeword length = 2^7 = 128 bits.
const rmBaseLen = 128

// rmEncodeBase encodes a single byte (8 bits) into a 128-bit RM(1,7) codeword.
// Returns two uint64 words [lo, hi] representing 128 bits.
func rmEncodeBase(msg byte) [2]uint64 {
	// The generator matrix rows for RM(1,7):
	// Row 0 (constant): all-ones = 0xFFFFFFFFFFFFFFFF (repeated)
	// Row 1: alternating 01010101... = 0xAAAAAAAAAAAAAAAA
	// Row 2: 00110011... = 0xCCCCCCCCCCCCCCCC
	// Row 3: 00001111... = 0xF0F0F0F0F0F0F0F0
	// Row 4: 0000000011111111... = 0xFF00FF00FF00FF00
	// Row 5: 16 zeros, 16 ones, ... = 0xFFFF0000FFFF0000
	// Row 6: 32 zeros, 32 ones, = 0xFFFFFFFF00000000
	//
	// For 128 bits we need two 64-bit words:
	// Row 7: first 64 zeros, next 64 ones = (0x0000000000000000, 0xFFFFFFFFFFFFFFFF)
	//
	// Message bit i selects row (i+1) in the traditional RM(1,m) generator matrix.
	// Bit 0 of msg is the constant term.

	var lo, hi uint64

	// bit0Mask expands bit 0 of msg to all 64 bits
	expand := func(bit uint) uint64 {
		return -(uint64((msg >> bit) & 1))
	}

	// Bit 0: constant row (all-ones if set)
	lo ^= expand(0)
	hi ^= expand(0)

	// Bit 1: row with pattern 0xAAAAAAAAAAAAAAAA
	lo ^= expand(1) & 0xAAAAAAAAAAAAAAAA
	hi ^= expand(1) & 0xAAAAAAAAAAAAAAAA

	// Bit 2: row with pattern 0xCCCCCCCCCCCCCCCC
	lo ^= expand(2) & 0xCCCCCCCCCCCCCCCC
	hi ^= expand(2) & 0xCCCCCCCCCCCCCCCC

	// Bit 3: row with pattern 0xF0F0F0F0F0F0F0F0
	lo ^= expand(3) & 0xF0F0F0F0F0F0F0F0
	hi ^= expand(3) & 0xF0F0F0F0F0F0F0F0

	// Bit 4: row with pattern 0xFF00FF00FF00FF00
	lo ^= expand(4) & 0xFF00FF00FF00FF00
	hi ^= expand(4) & 0xFF00FF00FF00FF00

	// Bit 5: row with pattern 0xFFFF0000FFFF0000
	lo ^= expand(5) & 0xFFFF0000FFFF0000
	hi ^= expand(5) & 0xFFFF0000FFFF0000

	// Bit 6: row with pattern 0xFFFFFFFF00000000
	lo ^= expand(6) & 0xFFFFFFFF00000000
	hi ^= expand(6) & 0xFFFFFFFF00000000

	// Bit 7: row (0x0000000000000000, 0xFFFFFFFFFFFFFFFF)
	hi ^= expand(7)

	return [2]uint64{lo, hi}
}

// rmDecode decodes an n2-bit received codeword (with duplicated RM(1,7))
// to a single byte using Walsh-Hadamard transform.
func rmDecode(src []uint64, n2, multiplicity int) byte {
	// Step 1: Accumulate all copies into a signed sum array of 128 entries.
	// Each bit position contributes +1 (if bit=1) or -1 (if bit=0).
	var sums [rmBaseLen]int32

	bitPos := 0
	for rep := 0; rep < multiplicity; rep++ {
		for i := 0; i < rmBaseLen; i++ {
			wordIdx := bitPos / 64
			bitIdx := uint(bitPos % 64)
			var bit int32
			if wordIdx < len(src) {
				bit = int32((src[wordIdx] >> bitIdx) & 1)
			}
			// Convert 0/1 to +1/-1 (0 -> +1, 1 -> -1)
			sums[i] += 1 - 2*bit
			bitPos++
		}
	}

	// Step 2: Fast Walsh-Hadamard Transform (in-place, 7 passes)
	for pass := 0; pass < 7; pass++ {
		step := 1 << uint(pass)
		for i := 0; i < rmBaseLen; i += 2 * step {
			for j := i; j < i+step; j++ {
				a := sums[j]
				b := sums[j+step]
				sums[j] = a + b
				sums[j+step] = a - b
			}
		}
	}

	// Step 3: Find the position with maximum absolute value
	maxAbs := int32(0)
	maxPos := 0
	sign := int32(1)

	for i := 0; i < rmBaseLen; i++ {
		v := sums[i]
		abs := v
		if abs < 0 {
			abs = -abs
		}
		if abs > maxAbs {
			maxAbs = abs
			maxPos = i
			if v > 0 {
				sign = 1
			} else {
				sign = -1
			}
		}
	}

	// Step 4: Recover the message byte.
	// maxPos encodes bits 1-7 of the message, sign encodes bit 0.
	// The codeword at position j is: c[j] = m0 XOR m1*j[0] XOR m2*j[1] ... XOR m7*j[6]
	// The WHT peak at position p means (m1,..,m7) = bits of p.
	// Negative sign means m0 = 1 (constant all-ones was applied).
	msg := byte(maxPos << 1)
	if sign < 0 {
		msg |= 1
	}
	return msg
}
