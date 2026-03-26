package slhdsa

import (
	"bytes"
	"testing"
)

func TestKeyGenSignVerifySHAKE128f(t *testing.T) {
	params := ParamsSHAKE128f
	pk, sk := KeyGen(params)

	if len(pk) != params.PKLen {
		t.Fatalf("pk length = %d, want %d", len(pk), params.PKLen)
	}
	if len(sk) != params.SKLen {
		t.Fatalf("sk length = %d, want %d", len(sk), params.SKLen)
	}

	msg := []byte("Hello, SLH-DSA!")
	sig := Sign(sk, msg, params)

	if len(sig) != params.SigLen {
		t.Fatalf("sig length = %d, want %d", len(sig), params.SigLen)
	}

	if !Verify(pk, msg, sig, params) {
		t.Fatal("valid signature rejected")
	}
}

func TestSignatureSizesSHAKE128f(t *testing.T) {
	params := ParamsSHAKE128f

	if params.SigLen != 17088 {
		t.Errorf("SHAKE-128f sig size = %d, want 17088", params.SigLen)
	}
	if params.PKLen != 32 {
		t.Errorf("SHAKE-128f pk size = %d, want 32", params.PKLen)
	}
	if params.SKLen != 64 {
		t.Errorf("SHAKE-128f sk size = %d, want 64", params.SKLen)
	}
}

func TestRejectTamperedSignature(t *testing.T) {
	params := ParamsSHAKE128f
	pk, sk := KeyGen(params)

	msg := []byte("test message")
	sig := Sign(sk, msg, params)

	// Tamper with signature
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[len(tampered)/2] ^= 0xFF

	if Verify(pk, msg, tampered, params) {
		t.Fatal("tampered signature accepted")
	}
}

func TestRejectTamperedMessage(t *testing.T) {
	params := ParamsSHAKE128f
	pk, sk := KeyGen(params)

	msg := []byte("test message")
	sig := Sign(sk, msg, params)

	wrongMsg := []byte("wrong message")
	if Verify(pk, wrongMsg, sig, params) {
		t.Fatal("signature verified with wrong message")
	}
}

func TestRejectWrongKey(t *testing.T) {
	params := ParamsSHAKE128f
	_, sk := KeyGen(params)
	pk2, _ := KeyGen(params)

	msg := []byte("test message")
	sig := Sign(sk, msg, params)

	if Verify(pk2, msg, sig, params) {
		t.Fatal("signature verified with wrong public key")
	}
}

func TestRejectWrongSigLength(t *testing.T) {
	params := ParamsSHAKE128f
	pk, _ := KeyGen(params)

	msg := []byte("test")
	shortSig := make([]byte, 100)
	if Verify(pk, msg, shortSig, params) {
		t.Fatal("short signature accepted")
	}
}

func TestKeyPairConsistency(t *testing.T) {
	params := ParamsSHAKE128f
	pk, sk := KeyGen(params)

	// PKseed and PKroot should appear in both pk and sk
	n := params.N
	pkSeedFromPK := pk[:n]
	pkSeedFromSK := sk[2*n : 3*n]
	if !bytes.Equal(pkSeedFromPK, pkSeedFromSK) {
		t.Error("PKseed mismatch between pk and sk")
	}

	pkRootFromPK := pk[n : 2*n]
	pkRootFromSK := sk[3*n : 4*n]
	if !bytes.Equal(pkRootFromPK, pkRootFromSK) {
		t.Error("PKroot mismatch between pk and sk")
	}
}

func TestAllParamSizes(t *testing.T) {
	expected := map[string]int{
		"SLH-DSA-SHAKE-128f": 17088,
		"SLH-DSA-SHAKE-128s": 7856,
		"SLH-DSA-SHAKE-192f": 35664,
		"SLH-DSA-SHAKE-192s": 16224,
		"SLH-DSA-SHAKE-256f": 49856,
		"SLH-DSA-SHAKE-256s": 29792,
		"SLH-DSA-SHA2-128f":  17088,
		"SLH-DSA-SHA2-128s":  7856,
		"SLH-DSA-SHA2-192f":  35664,
		"SLH-DSA-SHA2-192s":  16224,
		"SLH-DSA-SHA2-256f":  49856,
		"SLH-DSA-SHA2-256s":  29792,
	}

	for _, p := range AllParams() {
		exp, ok := expected[p.Name]
		if !ok {
			t.Errorf("unknown param set: %s", p.Name)
			continue
		}
		if p.SigLen != exp {
			t.Errorf("%s: sig size = %d, want %d", p.Name, p.SigLen, exp)
		}
	}
}

// AllParams re-exports for test access.
func AllParams() []*Params {
	return []*Params{
		ParamsSHAKE128f, ParamsSHAKE128s,
		ParamsSHAKE192f, ParamsSHAKE192s,
		ParamsSHAKE256f, ParamsSHAKE256s,
		ParamsSHA2128f, ParamsSHA2128s,
		ParamsSHA2192f, ParamsSHA2192s,
		ParamsSHA2256f, ParamsSHA2256s,
	}
}
