package hybrid

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func testRoundtrip(t *testing.T, scheme Scheme) {
	t.Helper()

	kp, err := KeyGen(scheme, rand.Reader)
	if err != nil {
		t.Fatalf("%s KeyGen failed: %v", scheme.Name, err)
	}

	enc, err := Encaps(scheme, kp.EK, kp.ClassicalEKSize, rand.Reader)
	if err != nil {
		t.Fatalf("%s Encaps failed: %v", scheme.Name, err)
	}

	ss, err := Decaps(scheme, kp.DK, enc.Ciphertext, kp.ClassicalDKSize, enc.ClassicalCTSize)
	if err != nil {
		t.Fatalf("%s Decaps failed: %v", scheme.Name, err)
	}

	if ss != enc.SharedSecret {
		t.Fatalf("%s roundtrip failed: shared secrets do not match", scheme.Name)
	}
}

func TestX25519MlKem768Roundtrip(t *testing.T) {
	testRoundtrip(t, X25519MlKem768)
}

func TestEcdhP256MlKem768Roundtrip(t *testing.T) {
	testRoundtrip(t, EcdhP256MlKem768)
}

func TestX25519MlKem1024Roundtrip(t *testing.T) {
	testRoundtrip(t, X25519MlKem1024)
}

func TestEcdhP384MlKem1024Roundtrip(t *testing.T) {
	testRoundtrip(t, EcdhP384MlKem1024)
}

func TestDifferentKeysDifferentSecrets(t *testing.T) {
	kp1, _ := KeyGen(X25519MlKem768, rand.Reader)
	kp2, _ := KeyGen(X25519MlKem768, rand.Reader)

	enc1, _ := Encaps(X25519MlKem768, kp1.EK, kp1.ClassicalEKSize, rand.Reader)
	enc2, _ := Encaps(X25519MlKem768, kp2.EK, kp2.ClassicalEKSize, rand.Reader)

	if enc1.SharedSecret == enc2.SharedSecret {
		t.Fatal("different keys should produce different shared secrets")
	}
}

func TestSharedSecretIs32Bytes(t *testing.T) {
	kp, _ := KeyGen(X25519MlKem768, rand.Reader)
	enc, _ := Encaps(X25519MlKem768, kp.EK, kp.ClassicalEKSize, rand.Reader)

	if len(enc.SharedSecret) != 32 {
		t.Fatalf("expected 32-byte shared secret, got %d", len(enc.SharedSecret))
	}
}

func TestMultipleEncapsSameKey(t *testing.T) {
	kp, _ := KeyGen(X25519MlKem768, rand.Reader)
	enc1, _ := Encaps(X25519MlKem768, kp.EK, kp.ClassicalEKSize, rand.Reader)
	enc2, _ := Encaps(X25519MlKem768, kp.EK, kp.ClassicalEKSize, rand.Reader)

	if bytes.Equal(enc1.SharedSecret[:], enc2.SharedSecret[:]) {
		t.Fatal("multiple encapsulations should produce different shared secrets")
	}

	ss1, _ := Decaps(X25519MlKem768, kp.DK, enc1.Ciphertext, kp.ClassicalDKSize, enc1.ClassicalCTSize)
	ss2, _ := Decaps(X25519MlKem768, kp.DK, enc2.Ciphertext, kp.ClassicalDKSize, enc2.ClassicalCTSize)

	if ss1 != enc1.SharedSecret {
		t.Fatal("first encapsulation roundtrip failed")
	}
	if ss2 != enc2.SharedSecret {
		t.Fatal("second encapsulation roundtrip failed")
	}
}
