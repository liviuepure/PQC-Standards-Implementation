package hqc

import (
	"bytes"
	"testing"
)

func TestGF256Tables(t *testing.T) {
	for i := 1; i < 256; i++ {
		a := byte(i)
		logA := gf256Log[a]
		expLogA := gf256Exp[logA]
		if expLogA != a {
			t.Errorf("exp(log(%d)) = %d, want %d", a, expLogA, a)
		}
	}
}

func TestGF256Mul(t *testing.T) {
	for i := 0; i < 256; i++ {
		a := byte(i)
		if gf256Mul(1, a) != a {
			t.Errorf("1 * %d = %d, want %d", a, gf256Mul(1, a), a)
		}
	}
	for i := 1; i < 256; i++ {
		a := byte(i)
		if gf256Mul(a, gf256Inv(a)) != 1 {
			t.Errorf("%d * inv(%d) != 1", a, a)
		}
	}
}

func TestGF256MulCT(t *testing.T) {
	for i := 0; i < 256; i++ {
		for j := 0; j < 256; j++ {
			a, b := byte(i), byte(j)
			if gf256MulCT(a, b) != gf256Mul(a, b) {
				t.Fatalf("gf256MulCT(%d,%d) mismatch", a, b)
			}
		}
	}
}

func TestGF2VectOps(t *testing.T) {
	a := []uint64{0xAAAA, 0x5555}
	b := []uint64{0x5555, 0xAAAA}
	c := vectAdd(a, b)
	if c[0] != 0xFFFF || c[1] != 0xFFFF {
		t.Errorf("vectAdd unexpected: %x %x", c[0], c[1])
	}

	// Mul by identity
	one := []uint64{1, 0}
	d := []uint64{0xDEADBEEFCAFEBABE, 0x1234567890ABCDEF}
	r := vectMul(d, one, 128)
	if r[0] != d[0] || r[1] != d[1] {
		t.Error("vectMul by 1 failed")
	}
}

func TestVectMulProperties(t *testing.T) {
	n := 17669
	se := newSeedExpander([]byte{99})
	h := vectSetRandomFixedWeight(se, n, 10)
	y := vectSetRandomFixedWeight(se, n, 10)
	r2 := vectSetRandomFixedWeight(se, n, 10)

	// Commutativity
	hy := vectMul(h, y, n)
	yh := vectMul(y, h, n)
	if vectEqual(hy, yh) != 1 {
		t.Error("not commutative")
	}

	// Associativity
	hy_r2 := vectMul(hy, r2, n)
	yr2 := vectMul(y, r2, n)
	h_yr2 := vectMul(h, yr2, n)
	if vectEqual(hy_r2, h_yr2) != 1 {
		t.Error("not associative")
	}
}

func TestRMEncodeDecodeRoundtrip(t *testing.T) {
	for msg := 0; msg < 256; msg++ {
		m := byte(msg)
		for _, mult := range []int{3, 5} {
			n2 := mult * 128
			nWords := (n2 + 63) / 64
			cw := make([]uint64, nWords)
			rmEncodeInto(cw, m, 0, mult)
			decoded := rmDecode(cw, n2, mult)
			if decoded != m {
				t.Errorf("RM mult=%d msg=%d: got %d", mult, msg, decoded)
			}
		}
	}
}

func TestRSEncodeDecodeRoundtrip(t *testing.T) {
	for _, p := range AllParams() {
		t.Run(p.Name, func(t *testing.T) {
			msg := make([]byte, p.K)
			for i := range msg {
				msg[i] = byte(i + 1)
			}
			cw := rsEncode(msg, p)
			decoded, ok := rsDecode(cw, p)
			if !ok {
				t.Fatal("decode failed on clean codeword")
			}
			if !bytes.Equal(decoded, msg) {
				t.Error("roundtrip mismatch")
			}
		})
	}
}

func TestRSDecodeWithErrors(t *testing.T) {
	for _, p := range AllParams() {
		t.Run(p.Name, func(t *testing.T) {
			msg := make([]byte, p.K)
			for i := range msg {
				msg[i] = byte(i*3 + 7)
			}
			cw := rsEncode(msg, p)
			for i := 0; i < p.Delta; i++ {
				cw[i] ^= byte(i + 1)
			}
			decoded, ok := rsDecode(cw, p)
			if !ok {
				t.Fatal("decode failed with correctable errors")
			}
			if !bytes.Equal(decoded, msg) {
				t.Error("decode mismatch after error correction")
			}
		})
	}
}

func TestTensorEncodeDecodeRoundtrip(t *testing.T) {
	for _, p := range AllParams() {
		t.Run(p.Name, func(t *testing.T) {
			msg := make([]byte, p.K)
			for i := range msg {
				msg[i] = byte(i + 42)
			}
			encoded := tensorEncode(msg, p)
			decoded, ok := tensorDecode(encoded, p)
			if !ok {
				t.Fatal("tensor decode failed")
			}
			if !bytes.Equal(decoded, msg) {
				t.Error("tensor roundtrip mismatch")
			}
		})
	}
}

func TestVectorWeights(t *testing.T) {
	for _, p := range AllParams() {
		t.Run(p.Name, func(t *testing.T) {
			se := newSeedExpander([]byte{1, 2, 3})
			for i := 0; i < 20; i++ {
				v := vectSetRandomFixedWeight(se, p.N, p.W)
				w := vectWeight(v)
				if w != p.W {
					t.Errorf("weight %d, expected %d", w, p.W)
				}
			}
		})
	}
}

func TestKEMRoundtrip(t *testing.T) {
	for _, p := range AllParams() {
		t.Run(p.Name, func(t *testing.T) {
			pk, sk, err := KeyGen(p, nil)
			if err != nil {
				t.Fatalf("KeyGen: %v", err)
			}
			if len(pk) != p.PKSize {
				t.Errorf("pk size = %d, want %d", len(pk), p.PKSize)
			}
			if len(sk) != p.SKSize {
				t.Errorf("sk size = %d, want %d", len(sk), p.SKSize)
			}

			ct, ss1, err := Encaps(pk, p, nil)
			if err != nil {
				t.Fatalf("Encaps: %v", err)
			}
			if len(ct) != p.CTSize {
				t.Errorf("ct size = %d, want %d", len(ct), p.CTSize)
			}
			if len(ss1) != p.SSSize {
				t.Errorf("ss size = %d, want %d", len(ss1), p.SSSize)
			}

			ss2, err := Decaps(sk, ct, p)
			if err != nil {
				t.Fatalf("Decaps: %v", err)
			}
			if !bytes.Equal(ss1, ss2) {
				t.Error("shared secrets don't match")
			}
		})
	}
}

func TestKEMDecapsBadCiphertext(t *testing.T) {
	p := HQC128
	pk, sk, err := KeyGen(p, nil)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	ct, ss1, err := Encaps(pk, p, nil)
	if err != nil {
		t.Fatalf("Encaps: %v", err)
	}
	ct[0] ^= 0xFF
	ct[1] ^= 0xFF
	ss2, err := Decaps(sk, ct, p)
	if err != nil {
		t.Fatalf("Decaps: %v", err)
	}
	if bytes.Equal(ss1, ss2) {
		t.Error("shared secrets should not match with corrupted ciphertext")
	}
}

func TestKEMMultipleRoundtrips(t *testing.T) {
	// Run multiple roundtrips per parameter set.
	// A correctly implemented HQC must never fail decapsulation,
	// so we require 100% success rate.
	for _, p := range AllParams() {
		t.Run(p.Name, func(t *testing.T) {
			trials := 20
			for i := 0; i < trials; i++ {
				pk, sk, err := KeyGen(p, nil)
				if err != nil {
					t.Fatalf("KeyGen: %v", err)
				}
				ct, ss1, err := Encaps(pk, p, nil)
				if err != nil {
					t.Fatalf("Encaps: %v", err)
				}
				ss2, err := Decaps(sk, ct, p)
				if err != nil {
					t.Fatalf("Decaps: %v", err)
				}
				if !bytes.Equal(ss1, ss2) {
					t.Fatalf("trial %d: shared secrets do not match", i)
				}
			}
			t.Logf("all %d roundtrips succeeded", trials)
		})
	}
}

func BenchmarkKeyGen(b *testing.B) {
	for _, p := range AllParams() {
		b.Run(p.Name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				KeyGen(p, nil)
			}
		})
	}
}

func BenchmarkEncaps(b *testing.B) {
	for _, p := range AllParams() {
		b.Run(p.Name, func(b *testing.B) {
			pk, _, _ := KeyGen(p, nil)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Encaps(pk, p, nil)
			}
		})
	}
}

func BenchmarkDecaps(b *testing.B) {
	for _, p := range AllParams() {
		b.Run(p.Name, func(b *testing.B) {
			pk, sk, _ := KeyGen(p, nil)
			ct, _, _ := Encaps(pk, p, nil)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Decaps(sk, ct, p)
			}
		})
	}
}
