// Package fndsa implements FN-DSA (FIPS 206 / FALCON) digital signatures.
//
// FN-DSA is a lattice-based signature scheme standardized by NIST in FIPS 206.
// It offers four parameter sets; the PADDED variants produce constant-length
// signatures eliminating a length side-channel.
//
// Usage:
//
//	pk, sk, err := fndsa.KeyGen(fndsa.FNDSA512, rand.Reader)
//	sig, err := fndsa.Sign(sk, msg, fndsa.FNDSA512, rand.Reader)
//	ok := fndsa.Verify(pk, msg, sig, fndsa.FNDSA512)
package fndsa

import (
	"io"

	"github.com/liviuepure/PQC-Standards-Implementation/go/internal/fndsa"
)

// Params is the FN-DSA parameter set.
type Params = fndsa.Params

// Pre-defined parameter sets per FIPS 206.
var (
	// FNDSA512 is the FN-DSA-512 parameter set (NIST security level 1, n=512).
	FNDSA512 = fndsa.FNDSA512
	// FNDSA1024 is the FN-DSA-1024 parameter set (NIST security level 5, n=1024).
	FNDSA1024 = fndsa.FNDSA1024
	// FNDSAPadded512 is FN-DSA-PADDED-512: constant-length signatures, n=512.
	FNDSAPadded512 = fndsa.FNDSAPadded512
	// FNDSAPadded1024 is FN-DSA-PADDED-1024: constant-length signatures, n=1024.
	FNDSAPadded1024 = fndsa.FNDSAPadded1024
)

// AllParams returns all defined FN-DSA parameter sets.
func AllParams() []*Params { return fndsa.AllParams() }

// KeyGen generates an FN-DSA key pair for parameter set p.
// Returns (pk, sk, nil) on success, or (nil, nil, err) on failure.
// rng must be a CSPRNG (e.g. crypto/rand.Reader).
func KeyGen(p *Params, rng io.Reader) (pk, sk []byte, err error) {
	f, g, F, _, err := fndsa.NTRUKeyGen(p, rng)
	if err != nil {
		return nil, nil, err
	}
	h := fndsa.NTRUPublicKey(f, g, p)
	pk = fndsa.EncodePK(h, p)
	sk = fndsa.EncodeSK(f, g, F, p)
	return pk, sk, nil
}

// Sign signs msg with secret key sk under parameter set p.
// Returns the encoded signature, or an error.
// rng must be a CSPRNG (e.g. crypto/rand.Reader).
func Sign(sk, msg []byte, p *Params, rng io.Reader) ([]byte, error) {
	return fndsa.SignInternal(sk, msg, p, rng)
}

// Verify checks that sig is a valid FN-DSA signature on msg under public key pk
// for parameter set p. Returns true iff the signature is valid.
func Verify(pk, msg, sig []byte, p *Params) bool {
	return fndsa.Verify(pk, msg, sig, p)
}
