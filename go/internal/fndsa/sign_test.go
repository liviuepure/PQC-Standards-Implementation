package fndsa

import (
	crypto_rand "crypto/rand"
	"testing"
)

// TestSignNormBound verifies ||(s1,s2)||² ≤ β² for each parameter set.
func TestSignNormBound(t *testing.T) {
	for _, p := range []*Params{FNDSA512, FNDSA1024} {
		p := p
		t.Run(p.Name, func(t *testing.T) {
			f, g, F, G, err := NTRUKeyGen(p, crypto_rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			h := NTRUPublicKey(f, g, p)
			sk := EncodeSK(f, g, F, p)
			_ = G
			msg := []byte("test message for norm bound check")
			sig, err := SignInternal(sk, msg, p, crypto_rand.Reader)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			salt, s1, ok := DecodeSig(sig, p)
			if !ok {
				t.Fatal("DecodeSig failed")
			}
			// Recompute s2 = HashToPoint(salt||msg) - s1*h mod q (centered)
			hashInput := append(salt, msg...)
			c := HashToPoint(hashInput, p)
			s1h := PolyMulNTT(
				func() []int32 {
					r := make([]int32, p.N)
					for i, v := range s1 {
						r[i] = ((v % Q) + Q) % Q
					}
					return r
				}(),
				h, p.N)
			s2 := make([]int32, p.N)
			for i := range s2 {
				s2[i] = centerModQ(c[i] - s1h[i])
			}
			norm := int64(0)
			for _, v := range s1 {
				norm += int64(v) * int64(v)
			}
			for _, v := range s2 {
				norm += int64(v) * int64(v)
			}
			if norm > int64(p.BetaSq) {
				t.Errorf("norm² = %d > β² = %d", norm, p.BetaSq)
			}
		})
	}
}

// TestHashToPointSize verifies HashToPoint returns n elements all in [0, Q).
func TestHashToPointSize(t *testing.T) {
	for _, p := range []*Params{FNDSA512, FNDSA1024} {
		p := p
		t.Run(p.Name, func(t *testing.T) {
			c := HashToPoint([]byte("test"), p)
			if len(c) != p.N {
				t.Fatalf("len=%d want %d", len(c), p.N)
			}
			for i, v := range c {
				if v < 0 || v >= Q {
					t.Errorf("c[%d]=%d out of [0,Q)", i, v)
				}
			}
		})
	}
}

// TestHashToPointDeterministic verifies HashToPoint is deterministic.
func TestHashToPointDeterministic(t *testing.T) {
	p := FNDSA512
	msg := []byte("deterministic test")
	c1 := HashToPoint(msg, p)
	c2 := HashToPoint(msg, p)
	for i := range c1 {
		if c1[i] != c2[i] {
			t.Fatalf("HashToPoint not deterministic at coeff %d", i)
		}
	}
}
