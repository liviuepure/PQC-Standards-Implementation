// Package fndsa implements FN-DSA (FIPS 206 / FALCON) digital signatures.
package fndsa

import (
	"github.com/liviuepure/PQC-Standards-Implementation/go/internal/fndsa"
)

// Params is the FN-DSA parameter set.
type Params = fndsa.Params

// Pre-defined parameter sets per FIPS 206.
var (
	FNDSA512        = fndsa.FNDSA512
	FNDSA1024       = fndsa.FNDSA1024
	FNDSAPadded512  = fndsa.FNDSAPadded512
	FNDSAPadded1024 = fndsa.FNDSAPadded1024
)
