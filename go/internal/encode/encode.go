// Package encode implements ByteEncode and ByteDecode per FIPS 203 Algorithms 5 and 6.
package encode

import (
	"github.com/baron-chain/PQC-Standards-Implementation/go/internal/field"
)

// ByteEncode encodes an array of 256 field elements into a byte slice using d bits per element.
// This is FIPS 203 Algorithm 5 (ByteEncode_d).
// d must be in [1, 12]. The output length is 32*d bytes.
func ByteEncode(d int, f *[256]field.Element) []byte {
	out := make([]byte, 32*d)
	// Pack 256 d-bit integers into a bit stream.
	// We accumulate bits in a buffer and flush whole bytes.
	bitBuf := uint64(0)
	bitLen := 0
	byteIdx := 0
	for i := 0; i < 256; i++ {
		val := uint64(f[i].Value())
		bitBuf |= val << bitLen
		bitLen += d
		for bitLen >= 8 {
			out[byteIdx] = byte(bitBuf & 0xFF)
			byteIdx++
			bitBuf >>= 8
			bitLen -= 8
		}
	}
	// Any remaining bits fit in a partial byte (should be zero remaining for 256*d mod 8 == 0
	// since d in {1..12} and 256*d is always divisible by 8).
	return out
}

// ByteDecode decodes a byte slice into an array of 256 field elements using d bits per element.
// This is FIPS 203 Algorithm 6 (ByteDecode_d).
// For d = 12 the decoded values are reduced modulo q.
// data must have length 32*d bytes.
func ByteDecode(d int, data []byte) [256]field.Element {
	var out [256]field.Element
	mask := uint64((1 << d) - 1)
	bitBuf := uint64(0)
	bitLen := 0
	byteIdx := 0
	for i := 0; i < 256; i++ {
		for bitLen < d {
			bitBuf |= uint64(data[byteIdx]) << bitLen
			byteIdx++
			bitLen += 8
		}
		val := uint16(bitBuf & mask)
		bitBuf >>= d
		bitLen -= d
		if d == 12 {
			val = val % field.Q
		}
		out[i] = field.Element(val)
	}
	return out
}
