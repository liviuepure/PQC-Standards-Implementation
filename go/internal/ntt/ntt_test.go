package ntt

import (
	"math/rand"
	"testing"

	"github.com/baron-chain/PQC-Standards-Implementation/go/internal/field"
)

func TestZetas(t *testing.T) {
	// Length check.
	if len(Zetas) != 128 {
		t.Fatalf("len(Zetas) = %d, want 128", len(Zetas))
	}

	// First entry: 17^BitRev7(0) = 17^0 = 1.
	if Zetas[0] != 1 {
		t.Errorf("Zetas[0] = %d, want 1", Zetas[0])
	}

	// Second entry: 17^BitRev7(1) = 17^64 mod 3329 = 1729.
	if Zetas[1] != 1729 {
		t.Errorf("Zetas[1] = %d, want 1729", Zetas[1])
	}

	// All values should be in [0, q).
	for i, z := range Zetas {
		if z >= field.Q {
			t.Errorf("Zetas[%d] = %d, out of range", i, z)
		}
	}

	// 17 is a primitive 256th root of unity: 17^256 ≡ 1 (mod 3329).
	// Verify using math/big or inline pow. Use standard library big.Int.
	// 17^128 mod 3329: compute iteratively.
	v := uint32(1)
	base := uint32(17)
	exp := uint32(128)
	b := base
	e := exp
	for e > 0 {
		if e&1 == 1 {
			v = (v * b) % 3329
		}
		e >>= 1
		b = (b * b) % 3329
	}
	if v != 3328 {
		t.Errorf("17^128 mod 3329 = %d, want 3328", v)
	}
}

func TestNTTRoundtrip(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	var f [256]field.Element
	for i := range f {
		f[i] = field.New(uint16(rng.Intn(int(field.Q))))
	}
	orig := f

	NTT(&f)
	NTTInverse(&f)

	for i := range f {
		if f[i] != orig[i] {
			t.Fatalf("roundtrip mismatch at index %d: got %d, want %d",
				i, f[i].Value(), orig[i].Value())
		}
	}
}

// TestPolyMultiplySimple verifies that (1+X)*(1+X) = 1+2X+X^2 via NTT.
func TestPolyMultiplySimple(t *testing.T) {
	var a, b [256]field.Element
	// a = 1 + X
	a[0] = field.New(1)
	a[1] = field.New(1)
	// b = 1 + X
	b[0] = field.New(1)
	b[1] = field.New(1)

	NTT(&a)
	NTT(&b)
	h := MultiplyNTTs(&a, &b)
	NTTInverse(&h)

	// Expected: h[0]=1, h[1]=2, h[2]=1, rest 0.
	expected := [256]field.Element{}
	expected[0] = field.New(1)
	expected[1] = field.New(2)
	expected[2] = field.New(1)

	for i := range h {
		if h[i] != expected[i] {
			t.Fatalf("poly multiply mismatch at index %d: got %d, want %d",
				i, h[i].Value(), expected[i].Value())
		}
	}
}

func TestMultiplyNTTsCommutative(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	var a, b [256]field.Element
	for i := range a {
		a[i] = field.New(uint16(rng.Intn(int(field.Q))))
		b[i] = field.New(uint16(rng.Intn(int(field.Q))))
	}

	NTT(&a)
	NTT(&b)

	ab := MultiplyNTTs(&a, &b)
	ba := MultiplyNTTs(&b, &a)

	for i := range ab {
		if ab[i] != ba[i] {
			t.Fatalf("commutativity failed at index %d: %d != %d",
				i, ab[i].Value(), ba[i].Value())
		}
	}
}

func TestMultiplyNTTsZero(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	var a, zero [256]field.Element
	for i := range a {
		a[i] = field.New(uint16(rng.Intn(int(field.Q))))
	}
	// zero is already all zeros.

	NTT(&a)
	NTT(&zero)

	h := MultiplyNTTs(&a, &zero)
	NTTInverse(&h)

	for i := range h {
		if h[i].Value() != 0 {
			t.Fatalf("multiply by zero non-zero at index %d: got %d", i, h[i].Value())
		}
	}
}
