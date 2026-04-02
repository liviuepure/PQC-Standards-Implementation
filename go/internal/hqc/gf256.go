package hqc

// GF(2^8) arithmetic with irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
// This is the polynomial specified by the HQC specification for Reed-Solomon encoding/decoding.

const (
	gfPoly     = 0x11D // x^8 + x^4 + x^3 + x^2 + 1
	gfGen      = 2     // primitive element (generator) for GF(2^8) with 0x11D (x is primitive)
	gfMulOrder = 255
)

var (
	gf256Exp [512]byte // exp table (doubled for convenience)
	gf256Log [256]byte // log table
)

func init() {
	initGF256Tables()
}

// initGF256Tables precomputes the log and exp tables for GF(2^8).
// Uses generator 2 (alpha = x), which is a primitive element for 0x11D.
func initGF256Tables() {
	var x uint16 = 1
	for i := 0; i < 255; i++ {
		gf256Exp[i] = byte(x)
		gf256Exp[i+255] = byte(x) // wrap-around for easy mod 255
		gf256Log[x] = byte(i)
		// Multiply x by the generator (2 = x in GF(2^8)):
		// x * 2 = x << 1, then reduce mod gfPoly if overflow
		x <<= 1
		if x >= 256 {
			x ^= gfPoly
		}
	}
	gf256Log[0] = 0 // convention: log(0) = 0 (never used for valid math)
	gf256Exp[510] = gf256Exp[0] // ensure full wrap
}

// gf256Add returns a + b in GF(2^8) (XOR).
func gf256Add(a, b byte) byte {
	return a ^ b
}

// gf256Mul returns a * b in GF(2^8) via log/exp tables.
func gf256Mul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gf256Exp[int(gf256Log[a])+int(gf256Log[b])]
}

// gf256MulCT performs constant-time GF(2^8) multiplication via carryless multiply.
// This avoids table lookups that could leak timing information.
func gf256MulCT(a, b byte) byte {
	var result uint16
	ab := uint16(a)
	bb := uint16(b)

	for i := 0; i < 8; i++ {
		result ^= ab * ((bb >> uint(i)) & 1)
		ab <<= 1
	}

	// Reduce mod x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
	for i := 14; i >= 8; i-- {
		if result&(1<<uint(i)) != 0 {
			result ^= uint16(gfPoly) << uint(i-8)
		}
	}
	return byte(result)
}

// gf256Inv returns the multiplicative inverse of a in GF(2^8).
// Returns 0 if a == 0.
func gf256Inv(a byte) byte {
	if a == 0 {
		return 0
	}
	return gf256Exp[255-int(gf256Log[a])]
}

// gf256Pow returns a^n in GF(2^8).
func gf256Pow(a byte, n int) byte {
	if a == 0 {
		if n == 0 {
			return 1
		}
		return 0
	}
	logA := int(gf256Log[a])
	logResult := (logA * n) % 255
	if logResult < 0 {
		logResult += 255
	}
	return gf256Exp[logResult]
}

// gf256Div returns a / b in GF(2^8). Panics if b == 0.
func gf256Div(a, b byte) byte {
	if b == 0 {
		panic("hqc: gf256 division by zero")
	}
	if a == 0 {
		return 0
	}
	logDiff := int(gf256Log[a]) - int(gf256Log[b])
	if logDiff < 0 {
		logDiff += 255
	}
	return gf256Exp[logDiff]
}
