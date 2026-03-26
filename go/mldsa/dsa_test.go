package mldsa

import (
	"testing"
)

func TestKeyGenSizes(t *testing.T) {
	tests := []struct {
		params  *Params
		pkSize  int
		skSize  int
	}{
		{MLDSA44, 1312, 2560},
		{MLDSA65, 1952, 4032},
		{MLDSA87, 2592, 4896},
	}
	for _, tc := range tests {
		t.Run(tc.params.Name, func(t *testing.T) {
			pk, sk := KeyGen(tc.params)
			if len(pk) != tc.pkSize {
				t.Errorf("%s: pk size = %d, want %d", tc.params.Name, len(pk), tc.pkSize)
			}
			if len(sk) != tc.skSize {
				t.Errorf("%s: sk size = %d, want %d", tc.params.Name, len(sk), tc.skSize)
			}
		})
	}
}

func TestSignVerifyRoundtrip(t *testing.T) {
	params := []*Params{MLDSA44, MLDSA65, MLDSA87}
	msg := []byte("test message for ML-DSA signature verification")

	for _, p := range params {
		t.Run(p.Name, func(t *testing.T) {
			pk, sk := KeyGen(p)

			sig := Sign(sk, msg, p)
			if len(sig) != p.SigSize {
				t.Errorf("%s: sig size = %d, want %d", p.Name, len(sig), p.SigSize)
			}

			if !Verify(pk, msg, sig, p) {
				t.Errorf("%s: valid signature rejected", p.Name)
			}
		})
	}
}

func TestRejectTamperedSignature(t *testing.T) {
	params := []*Params{MLDSA44, MLDSA65, MLDSA87}
	msg := []byte("test message")

	for _, p := range params {
		t.Run(p.Name, func(t *testing.T) {
			pk, sk := KeyGen(p)
			sig := Sign(sk, msg, p)

			// Tamper with signature
			tampered := make([]byte, len(sig))
			copy(tampered, sig)
			tampered[10] ^= 0xFF

			if Verify(pk, msg, tampered, p) {
				t.Errorf("%s: tampered signature accepted", p.Name)
			}
		})
	}
}

func TestRejectWrongMessage(t *testing.T) {
	params := []*Params{MLDSA44, MLDSA65, MLDSA87}

	for _, p := range params {
		t.Run(p.Name, func(t *testing.T) {
			pk, sk := KeyGen(p)
			sig := Sign(sk, []byte("correct message"), p)

			if Verify(pk, []byte("wrong message"), sig, p) {
				t.Errorf("%s: wrong message accepted", p.Name)
			}
		})
	}
}

func TestDeterministicKeyGen(t *testing.T) {
	xi := make([]byte, 32)
	for i := range xi {
		xi[i] = byte(i)
	}

	pk1, sk1 := KeyGenInternal(MLDSA44, xi)
	pk2, sk2 := KeyGenInternal(MLDSA44, xi)

	if !bytesEqual(pk1, pk2) {
		t.Error("deterministic keygen produced different public keys")
	}
	if !bytesEqual(sk1, sk2) {
		t.Error("deterministic keygen produced different secret keys")
	}
}

func TestCrossKeyReject(t *testing.T) {
	pk1, _ := KeyGen(MLDSA44)
	_, sk2 := KeyGen(MLDSA44)
	msg := []byte("test")

	sig := Sign(sk2, msg, MLDSA44)
	if Verify(pk1, msg, sig, MLDSA44) {
		t.Error("signature verified with wrong public key")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
