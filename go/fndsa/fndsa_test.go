package fndsa

import (
	crypto_rand "crypto/rand"
	"testing"
)

// TestRoundtrip exercises the full KeyGen → Sign → Verify pipeline for all
// four FN-DSA parameter sets, including tamper detection.
func TestRoundtrip(t *testing.T) {
	for _, p := range []*Params{FNDSA512, FNDSA1024, FNDSAPadded512, FNDSAPadded1024} {
		p := p // capture
		t.Run(p.Name, func(t *testing.T) {
			pk, sk, err := KeyGen(p, crypto_rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if len(pk) != p.PKSize {
				t.Errorf("pk size %d want %d", len(pk), p.PKSize)
			}
			if len(sk) != p.SKSize {
				t.Errorf("sk size %d want %d", len(sk), p.SKSize)
			}

			msg := []byte("test message for FN-DSA round-trip")
			sig, err := Sign(sk, msg, p, crypto_rand.Reader)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			// PADDED variants have fixed-length signatures; non-PADDED are variable.
			if p.Padded {
				if len(sig) != p.SigSize {
					t.Errorf("sig size %d want exactly %d (PADDED)", len(sig), p.SigSize)
				}
			} else {
				if len(sig) > p.SigSize {
					t.Errorf("sig size %d exceeds max %d", len(sig), p.SigSize)
				}
			}

			// Valid signature must verify.
			if !Verify(pk, msg, sig, p) {
				t.Error("valid signature rejected")
			}

			// Tampered signature must fail.
			tampered := make([]byte, len(sig))
			copy(tampered, sig)
			tampered[42] ^= 0x01
			if Verify(pk, msg, tampered, p) {
				t.Error("tampered signature accepted")
			}

			// Wrong message must fail.
			if Verify(pk, []byte("wrong"), sig, p) {
				t.Error("wrong-message verify accepted")
			}
		})
	}
}

func TestParamSizes(t *testing.T) {
	cases := []struct {
		p        *Params
		n        int
		pkBytes  int
		skBytes  int
		sigBytes int
	}{
		{FNDSA512, 512, 897, 1281, 666},
		{FNDSA1024, 1024, 1793, 2305, 1280},
		{FNDSAPadded512, 512, 897, 1281, 809},
		{FNDSAPadded1024, 1024, 1793, 2305, 1473},
	}
	for _, tc := range cases {
		t.Run(tc.p.Name, func(t *testing.T) {
			if tc.p.N != tc.n {
				t.Errorf("N=%d want %d", tc.p.N, tc.n)
			}
			if tc.p.PKSize != tc.pkBytes {
				t.Errorf("PKSize=%d want %d", tc.p.PKSize, tc.pkBytes)
			}
			if tc.p.SKSize != tc.skBytes {
				t.Errorf("SKSize=%d want %d", tc.p.SKSize, tc.skBytes)
			}
			if tc.p.SigSize != tc.sigBytes {
				t.Errorf("SigSize=%d want %d", tc.p.SigSize, tc.sigBytes)
			}
		})
	}
}
