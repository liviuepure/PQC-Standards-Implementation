package fndsa

// Q is the modulus used in FN-DSA (FIPS 206): q = 12289.
const Q = 12289

// Params holds the parameter set for an FN-DSA security level.
type Params struct {
	Name   string
	N      int     // polynomial degree (512 or 1024)
	LogN   int     // log2(N)
	Sigma  float64 // Gaussian standard deviation
	PKSize int     // public key size in bytes
	SKSize int     // secret key size in bytes
	// SigSize is the authoritative signature size used by callers:
	//   - for non-padded variants: maximum variable-length signature (SigMaxLen)
	//   - for padded variants: fixed padded-signature length
	SigSize int
	// SigMaxLen is the max variable-length signature before padding. Equals SigSize for non-padded variants.
	SigMaxLen int
	Padded    bool // true for FN-DSA-PADDED variants
	BetaSq    int  // β² bound for signature validity
}

// Pre-defined parameter sets per FIPS 206 Table 2.
var (
	// FNDSA512 is FN-DSA-512 (FALCON-512), targeting NIST security level 1.
	FNDSA512 = &Params{
		Name:      "FN-DSA-512",
		N:         512,
		LogN:      9,
		Sigma:     165.736617183,
		PKSize:    897,
		SKSize:    1281,
		SigSize:   666,
		SigMaxLen: 666,
		Padded:    false,
		BetaSq:    34034726,
	}

	// FNDSA1024 is FN-DSA-1024 (FALCON-1024), targeting NIST security level 5.
	FNDSA1024 = &Params{
		Name:      "FN-DSA-1024",
		N:         1024,
		LogN:      10,
		Sigma:     168.388571447,
		PKSize:    1793,
		SKSize:    2305,
		SigSize:   1280,
		SigMaxLen: 1280,
		Padded:    false,
		BetaSq:    70265242,
	}

	// FNDSAPadded512 is FN-DSA-PADDED-512 (FALCON-PADDED-512): same security
	// level as FNDSA512 but with a fixed-length padded signature format.
	FNDSAPadded512 = &Params{
		Name:      "FN-DSA-PADDED-512",
		N:         512,
		LogN:      9,
		Sigma:     165.736617183,
		PKSize:    897,
		SKSize:    1281,
		SigSize:   809,
		SigMaxLen: 666,
		Padded:    true,
		BetaSq:    34034726,
	}

	// FNDSAPadded1024 is FN-DSA-PADDED-1024 (FALCON-PADDED-1024): same
	// security level as FNDSA1024 but with a fixed-length padded signature.
	FNDSAPadded1024 = &Params{
		Name:      "FN-DSA-PADDED-1024",
		N:         1024,
		LogN:      10,
		Sigma:     168.388571447,
		PKSize:    1793,
		SKSize:    2305,
		SigSize:   1473,
		SigMaxLen: 1280,
		Padded:    true,
		BetaSq:    70265242,
	}
)

// AllParams returns all defined FN-DSA parameter sets.
func AllParams() []*Params {
	return []*Params{FNDSA512, FNDSA1024, FNDSAPadded512, FNDSAPadded1024}
}
