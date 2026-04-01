// Package fndsa implements FN-DSA (FIPS 206 / FALCON) digital signatures.
package fndsa

import (
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
