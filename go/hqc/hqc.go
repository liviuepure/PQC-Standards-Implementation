// Package hqc provides the public API for the HQC (Hamming Quasi-Cyclic) KEM.
//
// HQC is a code-based key encapsulation mechanism selected by NIST for
// post-quantum cryptography standardization. It serves as a backup to ML-KEM,
// providing algorithmic diversity based on the hardness of syndrome decoding.
//
// Three security levels are supported:
//   - HQC-128: NIST security level 1 (128-bit)
//   - HQC-192: NIST security level 3 (192-bit)
//   - HQC-256: NIST security level 5 (256-bit)
package hqc

import (
	"errors"
	"io"

	"github.com/liviuepure/PQC-Standards-Implementation/go/internal/hqc"
)

// Params holds the parameter set for an HQC security level.
type Params = hqc.Params

// Pre-defined parameter sets.
var (
	HQC128 = hqc.HQC128
	HQC192 = hqc.HQC192
	HQC256 = hqc.HQC256
)

// AllParams returns all supported HQC parameter sets.
func AllParams() []*Params {
	return hqc.AllParams()
}

// KeyGen generates an HQC key pair for the given parameter set.
// If rng is nil, crypto/rand.Reader is used.
// Returns (publicKey, secretKey, error).
func KeyGen(p *Params, rng io.Reader) (pk, sk []byte, err error) {
	if p == nil {
		return nil, nil, errors.New("hqc: nil params")
	}
	return hqc.KeyGen(p, rng)
}

// Encaps encapsulates a shared secret using the given public key.
// If rng is nil, crypto/rand.Reader is used.
// Returns (ciphertext, sharedSecret, error).
func Encaps(pk []byte, p *Params, rng io.Reader) (ct, ss []byte, err error) {
	if p == nil {
		return nil, nil, errors.New("hqc: nil params")
	}
	if len(pk) != p.PKSize {
		return nil, nil, errors.New("hqc: invalid public key size")
	}
	return hqc.Encaps(pk, p, rng)
}

// Decaps decapsulates a shared secret from a ciphertext using the secret key.
// Returns (sharedSecret, error).
func Decaps(sk, ct []byte, p *Params) (ss []byte, err error) {
	if p == nil {
		return nil, errors.New("hqc: nil params")
	}
	if len(sk) != p.SKSize {
		return nil, errors.New("hqc: invalid secret key size")
	}
	if len(ct) != p.CTSize {
		return nil, errors.New("hqc: invalid ciphertext size")
	}
	return hqc.Decaps(sk, ct, p)
}
