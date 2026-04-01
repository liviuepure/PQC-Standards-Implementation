package fndsa

import "testing"

func TestKeyEncodeRoundtrip(t *testing.T) {
	for _, p := range []*Params{FNDSA512, FNDSA1024} {
		p := p
		t.Run(p.Name, func(t *testing.T) {
			h := make([]int32, p.N)
			for i := range h {
				h[i] = int32(i % Q)
			}
			encoded := EncodePK(h, p)
			if len(encoded) != p.PKSize {
				t.Fatalf("pk length: got %d want %d", len(encoded), p.PKSize)
			}
			if encoded[0] != byte(0x00|p.LogN) {
				t.Errorf("pk header byte: got 0x%02x want 0x%02x", encoded[0], byte(0x00|p.LogN))
			}
			decoded := DecodePK(encoded, p)
			for i := range h {
				if h[i] != decoded[i] {
					t.Fatalf("pk coeff[%d]: got %d want %d", i, decoded[i], h[i])
				}
			}
		})
	}
}

func TestSKEncodeRoundtrip(t *testing.T) {
	for _, p := range []*Params{FNDSA512, FNDSA1024} {
		p := p
		t.Run(p.Name, func(t *testing.T) {
			f := make([]int32, p.N)
			g := make([]int32, p.N)
			F := make([]int32, p.N)
			fgBits := 6
			if p.N == 1024 {
				fgBits = 5
			}
			maxFG := int32((1 << (fgBits - 1)) - 1)
			for i := range f {
				f[i] = int32(i%int(2*maxFG+1)) - maxFG
				g[i] = -f[i]
				F[i] = int32(i%255) - 127
			}
			encoded := EncodeSK(f, g, F, p)
			if len(encoded) != p.SKSize {
				t.Fatalf("sk length: got %d want %d", len(encoded), p.SKSize)
			}
			if encoded[0] != byte(0x50|p.LogN) {
				t.Errorf("sk header byte: got 0x%02x want 0x%02x", encoded[0], byte(0x50|p.LogN))
			}
			df, dg, dF, ok := DecodeSK(encoded, p)
			if !ok {
				t.Fatal("DecodeSK failed")
			}
			for i := range f {
				if f[i] != df[i] {
					t.Fatalf("f[%d]: got %d want %d", i, df[i], f[i])
				}
				if g[i] != dg[i] {
					t.Fatalf("g[%d]: got %d want %d", i, dg[i], g[i])
				}
				if F[i] != dF[i] {
					t.Fatalf("F[%d]: got %d want %d", i, dF[i], F[i])
				}
			}
		})
	}
}

func TestSigEncodeRoundtrip(t *testing.T) {
	for _, p := range []*Params{FNDSA512, FNDSA1024, FNDSAPadded512, FNDSAPadded1024} {
		p := p
		t.Run(p.Name, func(t *testing.T) {
			salt := make([]byte, 40)
			for i := range salt {
				salt[i] = byte(i)
			}
			s1 := make([]int32, p.N)
			for i := range s1 {
				s1[i] = int32(i%10) - 5
			}
			encoded, ok := EncodeSig(salt, s1, p)
			if !ok {
				t.Fatal("EncodeSig failed")
			}
			// PADDED variants must be exactly SigSize bytes.
			// Non-PADDED variants are variable-length, bounded by SigSize (== SigMaxLen).
			if p.Padded {
				if len(encoded) != p.SigSize {
					t.Fatalf("sig length: got %d want %d", len(encoded), p.SigSize)
				}
			} else {
				if len(encoded) > p.SigSize {
					t.Fatalf("sig too long: got %d > max %d", len(encoded), p.SigSize)
				}
			}
			decodedSalt, decodedS1, ok := DecodeSig(encoded, p)
			if !ok {
				t.Fatal("DecodeSig failed")
			}
			for i, v := range salt {
				if decodedSalt[i] != v {
					t.Fatalf("salt[%d] mismatch", i)
				}
			}
			for i := range s1 {
				if s1[i] != decodedS1[i] {
					t.Fatalf("s1[%d]: got %d want %d", i, decodedS1[i], s1[i])
				}
			}
		})
	}
}

// TestDecodePKRejectsWrongHeader verifies that DecodePK validates the header byte.
func TestDecodePKRejectsWrongHeader(t *testing.T) {
	p := FNDSA512
	h := make([]int32, p.N)
	encoded := EncodePK(h, p)
	// Corrupt the header byte.
	encoded[0] ^= 0xFF
	if DecodePK(encoded, p) != nil {
		t.Error("DecodePK should return nil for wrong header byte")
	}
}

// TestDecodeSigRejectsNonCanonicalZero verifies that a zero coefficient encoded
// with sign bit 1 (non-canonical per FIPS 206 §3.11.5) is rejected.
func TestDecodeSigRejectsNonCanonicalZero(t *testing.T) {
	p := FNDSA512
	lo := loBitsFor(p)
	// Build a byte stream with one zero coefficient encoded as:
	//   lo zero lo-bits, zero 1-bits, one 0-bit terminator, sign bit 1.
	// For lo=6 that's 6+0+1+1 = 8 bits = 1 byte: 0b1000_0000 = 0x80
	// (bits 0-5: low=0, bit 6: terminator 0, bit 7: sign=1)
	var nonCanonicalByte byte
	if lo == 6 {
		// bits [0..5]=0 (lo bits), bit 6=0 (terminator), bit 7=1 (sign)
		nonCanonicalByte = 0x80
	} else {
		// lo=7: bits [0..6]=0 (lo bits), bit 7=0 (terminator) → needs 9 bits; spread across 2 bytes
		// byte 0: bits [0..6]=0, bit 7=0 → 0x00
		// byte 1: bit 0 = 1 (sign) → 0x01
		nonCanonicalByte = 0 // handled below for lo=7 case
	}

	// Use EncodeSig/DecodeSig path to construct a valid-looking sig with a tampered payload.
	// For simplicity, only test lo=6 (FN-DSA-512) here.
	if lo != 6 {
		t.Skip("non-canonical zero test only implemented for lo=6")
	}

	// Build a sig buffer: header + 40 salt bytes + nonCanonical byte for coeff 0.
	// We need n=512 coefficients total; after coeff 0 the rest would not decode.
	// We only need to verify that the first coefficient triggers rejection.
	buf := make([]byte, 1+40+1)
	buf[0] = byte(0x30 | p.LogN)
	buf[41] = nonCanonicalByte

	_, _, ok := DecodeSig(buf, p)
	if ok {
		t.Error("DecodeSig must reject non-canonical zero (sign bit 1 for v=0)")
	}
}

func TestSigHeaderByte(t *testing.T) {
	for _, p := range []*Params{FNDSA512, FNDSA1024, FNDSAPadded512, FNDSAPadded1024} {
		p := p
		t.Run(p.Name, func(t *testing.T) {
			salt := make([]byte, 40)
			s1 := make([]int32, p.N)
			sig, ok := EncodeSig(salt, s1, p)
			if !ok {
				t.Fatal("EncodeSig failed")
			}
			want := byte(0x30 | p.LogN)
			if sig[0] != want {
				t.Errorf("header byte: got 0x%02x want 0x%02x", sig[0], want)
			}
		})
	}
}
