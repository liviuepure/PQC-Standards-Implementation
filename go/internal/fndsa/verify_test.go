package fndsa

import (
	crypto_rand "crypto/rand"
	"testing"
)

func TestVerifyValid(t *testing.T) {
	for _, p := range []*Params{FNDSA512, FNDSA1024} {
		p := p
		t.Run(p.Name, func(t *testing.T) {
			f, g, F, _, err := NTRUKeyGen(p, crypto_rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			h := NTRUPublicKey(f, g, p)
			pk := EncodePK(h, p)
			sk := EncodeSK(f, g, F, p)
			msg := []byte("hello fn-dsa verify")
			sig, err := SignInternal(sk, msg, p, crypto_rand.Reader)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !Verify(pk, msg, sig, p) {
				t.Error("valid signature rejected")
			}
		})
	}
}

func TestVerifyTamperedSig(t *testing.T) {
	for _, p := range []*Params{FNDSA512, FNDSA1024} {
		p := p
		t.Run(p.Name, func(t *testing.T) {
			f, g, F, _, err := NTRUKeyGen(p, crypto_rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			h := NTRUPublicKey(f, g, p)
			pk := EncodePK(h, p)
			sk := EncodeSK(f, g, F, p)
			msg := []byte("tamper test")
			sig, err := SignInternal(sk, msg, p, crypto_rand.Reader)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			// Corrupt one byte of the compressed s1 region (after header + 40 salt bytes)
			sig[42] ^= 0xFF
			if Verify(pk, msg, sig, p) {
				t.Error("tampered signature accepted")
			}
		})
	}
}

func TestVerifyWrongMessage(t *testing.T) {
	for _, p := range []*Params{FNDSA512, FNDSA1024} {
		p := p
		t.Run(p.Name, func(t *testing.T) {
			f, g, F, _, err := NTRUKeyGen(p, crypto_rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			h := NTRUPublicKey(f, g, p)
			pk := EncodePK(h, p)
			sk := EncodeSK(f, g, F, p)
			sig, err := SignInternal(sk, []byte("original"), p, crypto_rand.Reader)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if Verify(pk, []byte("different"), sig, p) {
				t.Error("wrong-message verify accepted")
			}
		})
	}
}

func TestVerifyWrongPublicKey(t *testing.T) {
	p := FNDSA512
	f, g, F, _, err := NTRUKeyGen(p, crypto_rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := NTRUPublicKey(f, g, p)
	sk := EncodeSK(f, g, F, p)
	msg := []byte("wrong pk test")
	sig, err := SignInternal(sk, msg, p, crypto_rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Generate a different public key
	f2, g2, _, _, err := NTRUKeyGen(p, crypto_rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h2 := NTRUPublicKey(f2, g2, p)
	_ = h
	pk2 := EncodePK(h2, p)
	if Verify(pk2, msg, sig, p) {
		t.Error("verification with wrong public key accepted")
	}
}

func TestVerifyMalformedInputs(t *testing.T) {
	p := FNDSA512
	f, g, F, _, err := NTRUKeyGen(p, crypto_rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := NTRUPublicKey(f, g, p)
	pk := EncodePK(h, p)
	sk := EncodeSK(f, g, F, p)
	msg := []byte("test")
	sig, err := SignInternal(sk, msg, p, crypto_rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("nil pk", func(t *testing.T) {
		if Verify(nil, msg, sig, p) {
			t.Error("nil pk accepted")
		}
	})
	t.Run("nil sig", func(t *testing.T) {
		if Verify(pk, msg, nil, p) {
			t.Error("nil sig accepted")
		}
	})
	t.Run("short sig", func(t *testing.T) {
		if Verify(pk, msg, sig[:10], p) {
			t.Error("short sig accepted")
		}
	})
	t.Run("wrong pk header", func(t *testing.T) {
		bad := make([]byte, len(pk))
		copy(bad, pk)
		bad[0] ^= 0xFF
		if Verify(bad, msg, sig, p) {
			t.Error("wrong pk header accepted")
		}
	})
}
