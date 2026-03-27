// Package hybrid implements Hybrid KEM schemes combining classical
// ECDH key exchange with ML-KEM for post-quantum/classical security.
//
// The combiner ensures security holds if either the classical or
// post-quantum component remains secure.
//
// Supported schemes:
//   - X25519 + ML-KEM-768 (IETF standard hybrid for TLS)
//   - ECDH-P256 + ML-KEM-768
//   - X25519 + ML-KEM-1024 (higher security)
//   - ECDH-P384 + ML-KEM-1024
//
// KDF: SHA3-256(ss_classical || ss_pq || label)
package hybrid

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/baron-chain/PQC-Standards-Implementation/go/internal/params"
	"github.com/baron-chain/PQC-Standards-Implementation/go/mlkem"
)

// Scheme identifies a hybrid KEM scheme.
type Scheme struct {
	Name           string
	ClassicalCurve ecdh.Curve
	MLKEMParams    params.ParameterSet
	Label          []byte
}

var (
	// X25519MlKem768 combines X25519 with ML-KEM-768.
	X25519MlKem768 = Scheme{
		Name:           "X25519-MLKEM768",
		ClassicalCurve: ecdh.X25519(),
		MLKEMParams:    params.MlKem768,
		Label:          []byte("X25519-MLKEM768"),
	}

	// EcdhP256MlKem768 combines ECDH-P256 with ML-KEM-768.
	EcdhP256MlKem768 = Scheme{
		Name:           "ECDHP256-MLKEM768",
		ClassicalCurve: ecdh.P256(),
		MLKEMParams:    params.MlKem768,
		Label:          []byte("ECDHP256-MLKEM768"),
	}

	// X25519MlKem1024 combines X25519 with ML-KEM-1024.
	X25519MlKem1024 = Scheme{
		Name:           "X25519-MLKEM1024",
		ClassicalCurve: ecdh.X25519(),
		MLKEMParams:    params.MlKem1024,
		Label:          []byte("X25519-MLKEM1024"),
	}

	// EcdhP384MlKem1024 combines ECDH-P384 with ML-KEM-1024.
	EcdhP384MlKem1024 = Scheme{
		Name:           "ECDHP384-MLKEM1024",
		ClassicalCurve: ecdh.P384(),
		MLKEMParams:    params.MlKem1024,
		Label:          []byte("ECDHP384-MLKEM1024"),
	}
)

// HybridKeyPair holds a hybrid key pair.
type HybridKeyPair struct {
	// EK is the combined encapsulation key (classical_pk || pq_ek).
	EK []byte
	// DK is the combined decapsulation key (classical_sk || pq_dk).
	DK []byte
	// ClassicalEKSize is the size of the classical public key portion.
	ClassicalEKSize int
	// ClassicalDKSize is the size of the classical secret key portion.
	ClassicalDKSize int
}

// EncapsResult holds the result of hybrid encapsulation.
type EncapsResult struct {
	// SharedSecret is the combined 32-byte shared secret.
	SharedSecret [32]byte
	// Ciphertext is the combined ciphertext (classical_ct || pq_ct).
	Ciphertext []byte
	// ClassicalCTSize is the size of the classical ciphertext portion.
	ClassicalCTSize int
}

// combineSecrets derives the hybrid shared secret using SHA3-256.
func combineSecrets(ssClassical, ssPQ, label []byte) [32]byte {
	h := sha3.New256()
	h.Write(ssClassical)
	h.Write(ssPQ)
	h.Write(label)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// KeyGen generates a hybrid key pair using the specified scheme.
func KeyGen(scheme Scheme, rng io.Reader) (*HybridKeyPair, error) {
	if rng == nil {
		rng = rand.Reader
	}

	// Classical key generation
	classicalSK, err := scheme.ClassicalCurve.GenerateKey(rng)
	if err != nil {
		return nil, errors.New("hybrid: classical keygen failed: " + err.Error())
	}
	classicalPK := classicalSK.PublicKey().Bytes()
	classicalSKBytes := classicalSK.Bytes()

	// ML-KEM key generation
	pqEK, pqDK, err := mlkem.KeyGen(scheme.MLKEMParams, rng)
	if err != nil {
		return nil, errors.New("hybrid: ML-KEM keygen failed: " + err.Error())
	}

	// Combine keys
	ek := make([]byte, 0, len(classicalPK)+len(pqEK))
	ek = append(ek, classicalPK...)
	ek = append(ek, pqEK...)

	dk := make([]byte, 0, len(classicalSKBytes)+len(pqDK))
	dk = append(dk, classicalSKBytes...)
	dk = append(dk, pqDK...)

	return &HybridKeyPair{
		EK:              ek,
		DK:              dk,
		ClassicalEKSize: len(classicalPK),
		ClassicalDKSize: len(classicalSKBytes),
	}, nil
}

// Encaps encapsulates using the hybrid scheme, producing a shared secret and ciphertext.
func Encaps(scheme Scheme, ek []byte, classicalEKSize int, rng io.Reader) (*EncapsResult, error) {
	if rng == nil {
		rng = rand.Reader
	}

	classicalPKBytes := ek[:classicalEKSize]
	pqEK := ek[classicalEKSize:]

	// Parse the classical public key
	classicalPK, err := scheme.ClassicalCurve.NewPublicKey(classicalPKBytes)
	if err != nil {
		return nil, errors.New("hybrid: invalid classical public key: " + err.Error())
	}

	// Classical ECDH encapsulation: generate ephemeral key pair, DH
	ephSK, err := scheme.ClassicalCurve.GenerateKey(rng)
	if err != nil {
		return nil, errors.New("hybrid: classical ephemeral keygen failed: " + err.Error())
	}
	ssClassical, err := ephSK.ECDH(classicalPK)
	if err != nil {
		return nil, errors.New("hybrid: classical ECDH failed: " + err.Error())
	}
	ctClassical := ephSK.PublicKey().Bytes()

	// ML-KEM encapsulation
	ssPQ, ctPQ, err := mlkem.Encapsulate(scheme.MLKEMParams, pqEK, rng)
	if err != nil {
		return nil, errors.New("hybrid: ML-KEM encaps failed: " + err.Error())
	}

	combinedSS := combineSecrets(ssClassical, ssPQ[:], scheme.Label)

	ct := make([]byte, 0, len(ctClassical)+len(ctPQ))
	ct = append(ct, ctClassical...)
	ct = append(ct, ctPQ...)

	return &EncapsResult{
		SharedSecret:    combinedSS,
		Ciphertext:      ct,
		ClassicalCTSize: len(ctClassical),
	}, nil
}

// Decaps decapsulates using the hybrid scheme, recovering the shared secret.
func Decaps(scheme Scheme, dk, ct []byte, classicalDKSize, classicalCTSize int) ([32]byte, error) {
	classicalSKBytes := dk[:classicalDKSize]
	pqDK := dk[classicalDKSize:]

	ctClassical := ct[:classicalCTSize]
	ctPQ := ct[classicalCTSize:]

	// Parse the classical secret key
	classicalSK, err := scheme.ClassicalCurve.NewPrivateKey(classicalSKBytes)
	if err != nil {
		return [32]byte{}, errors.New("hybrid: invalid classical secret key: " + err.Error())
	}

	// Parse the ephemeral public key from ciphertext
	ephPK, err := scheme.ClassicalCurve.NewPublicKey(ctClassical)
	if err != nil {
		return [32]byte{}, errors.New("hybrid: invalid classical ciphertext: " + err.Error())
	}

	// Classical ECDH decapsulation
	ssClassical, err := classicalSK.ECDH(ephPK)
	if err != nil {
		return [32]byte{}, errors.New("hybrid: classical ECDH decaps failed: " + err.Error())
	}

	// ML-KEM decapsulation
	ssPQ := mlkem.Decapsulate(scheme.MLKEMParams, pqDK, ctPQ)

	combinedSS := combineSecrets(ssClassical, ssPQ[:], scheme.Label)
	return combinedSS, nil
}
