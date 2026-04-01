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

func TestSigHeaderByte(t *testing.T) {
	for _, p := range []*Params{FNDSA512, FNDSA1024} {
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
