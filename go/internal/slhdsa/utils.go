package slhdsa

// toInt interprets a byte slice as a big-endian unsigned integer.
// FIPS 205 Algorithm 1: toInt(X, n).
func toInt(x []byte) uint64 {
	var total uint64
	for _, b := range x {
		total = (total << 8) | uint64(b)
	}
	return total
}

// toByte converts a non-negative integer to a big-endian byte string of length outLen.
// FIPS 205 Algorithm 2: toByte(x, n).
func toByte(x uint64, outLen int) []byte {
	b := make([]byte, outLen)
	for i := outLen - 1; i >= 0; i-- {
		b[i] = byte(x & 0xff)
		x >>= 8
	}
	return b
}

// base2b splits a byte string into base-2^b integers.
// FIPS 205 Algorithm 3: base_2b(X, b, out_len).
// Returns out_len integers, each in [0, 2^b - 1].
func base2b(x []byte, b int, outLen int) []int {
	result := make([]int, outLen)
	inIdx := 0
	bits := 0
	var buf uint64

	for i := 0; i < outLen; i++ {
		for bits < b {
			if inIdx < len(x) {
				buf = (buf << 8) | uint64(x[inIdx])
				inIdx++
			} else {
				buf <<= 8
			}
			bits += 8
		}
		bits -= b
		result[i] = int((buf >> uint(bits)) & ((1 << uint(b)) - 1))
	}
	return result
}
