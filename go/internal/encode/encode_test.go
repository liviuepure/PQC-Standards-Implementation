package encode

import (
	"testing"

	"github.com/baron-chain/PQC-Standards-Implementation/go/internal/field"
)

// testRoundTrip verifies that ByteDecode(ByteEncode(f)) == f for a given d.
func testRoundTrip(t *testing.T, d int) {
	t.Helper()
	var f [256]field.Element
	maxVal := uint16((1 << d) - 1)
	if d == 12 {
		maxVal = field.Q - 1
	}
	// Fill with a mix of values including 0, max, and varying middle values.
	for i := 0; i < 256; i++ {
		v := uint16(i) % (maxVal + 1)
		f[i] = field.Element(v)
	}

	encoded := ByteEncode(d, &f)
	if len(encoded) != 32*d {
		t.Fatalf("ByteEncode(%d): got length %d, want %d", d, len(encoded), 32*d)
	}

	decoded := ByteDecode(d, encoded)
	for i := 0; i < 256; i++ {
		if decoded[i] != f[i] {
			t.Fatalf("round-trip d=%d: index %d: got %d, want %d", d, i, decoded[i].Value(), f[i].Value())
		}
	}
}

func TestRoundTripD1(t *testing.T)  { testRoundTrip(t, 1) }
func TestRoundTripD4(t *testing.T)  { testRoundTrip(t, 4) }
func TestRoundTripD10(t *testing.T) { testRoundTrip(t, 10) }
func TestRoundTripD12(t *testing.T) { testRoundTrip(t, 12) }

func TestByteEncodeLength(t *testing.T) {
	for _, d := range []int{1, 4, 10, 11, 12} {
		var f [256]field.Element
		encoded := ByteEncode(d, &f)
		if len(encoded) != 32*d {
			t.Errorf("ByteEncode(%d): length = %d, want %d", d, len(encoded), 32*d)
		}
	}
}

func TestByteDecodeD12ReducesModQ(t *testing.T) {
	// Craft input where a decoded 12-bit value exceeds q.
	// Place value 3329 (= q) at the first position: 3329 in 12 bits = 0xD01.
	// The first 12 bits come from bytes 0 and 1 (lower 4 bits of byte 1).
	data := make([]byte, 32*12)
	// 3329 = 0xD01 in 12 bits. Bit-stream packing: bits 0-7 in byte[0], bits 8-11 in lower nibble of byte[1].
	data[0] = 0x01 // low 8 bits of 0xD01
	data[1] = 0x0D // high 4 bits of 0xD01 in lower nibble (upper nibble = 0 for second element)
	decoded := ByteDecode(12, data)
	if decoded[0].Value() != 0 {
		t.Errorf("ByteDecode(12) did not reduce mod q: got %d, want 0", decoded[0].Value())
	}
}

func TestRoundTripAllZeros(t *testing.T) {
	for _, d := range []int{1, 4, 10, 12} {
		var f [256]field.Element
		encoded := ByteEncode(d, &f)
		decoded := ByteDecode(d, encoded)
		for i := 0; i < 256; i++ {
			if decoded[i].Value() != 0 {
				t.Fatalf("d=%d: zero round-trip failed at index %d: got %d", d, i, decoded[i].Value())
			}
		}
	}
}

func TestRoundTripMaxValues(t *testing.T) {
	for _, d := range []int{1, 4, 10} {
		var f [256]field.Element
		maxVal := uint16((1 << d) - 1)
		for i := range f {
			f[i] = field.Element(maxVal)
		}
		encoded := ByteEncode(d, &f)
		decoded := ByteDecode(d, encoded)
		for i := 0; i < 256; i++ {
			if decoded[i].Value() != maxVal {
				t.Fatalf("d=%d: max round-trip failed at index %d: got %d, want %d", d, i, decoded[i].Value(), maxVal)
			}
		}
	}
}
