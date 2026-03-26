// Package slhdsa implements the internal components of SLH-DSA (FIPS 205).
package slhdsa

// Params holds the parameters for an SLH-DSA instance.
type Params struct {
	Name string // e.g. "SLH-DSA-SHAKE-128f"

	N   int // Security parameter (hash output length in bytes)
	H   int // Total tree height
	D   int // Number of layers in hypertree
	HP  int // Height of each tree (h/d)
	A   int // FORS tree height
	K   int // Number of FORS trees
	W   int // Winternitz parameter (always 16)
	Len int // WOTS+ signature length in n-byte strings

	PKLen  int // Public key length
	SKLen  int // Secret key length
	SigLen int // Signature length

	IsSHA2 bool // true for SHA2 variants, false for SHAKE
}

// computeSizes fills in PKLen, SKLen, SigLen from the other parameters.
func (p *Params) computeSizes() {
	p.PKLen = 2 * p.N
	p.SKLen = 4 * p.N
	// Sig = n + k*(1+a)*n + d*(len+hp)*n
	//     = n * (1 + k*(1+a) + d*(len+hp))
	p.SigLen = p.N * (1 + p.K*(1+p.A) + p.D*(p.Len+p.HP))
}

func newParams(name string, n, h, d, a, k int, isSHA2 bool) *Params {
	hp := h / d
	l := 2*n + 3 // len for w=16
	p := &Params{
		Name:   name,
		N:      n,
		H:      h,
		D:      d,
		HP:     hp,
		A:      a,
		K:      k,
		W:      16,
		Len:    l,
		IsSHA2: isSHA2,
	}
	p.computeSizes()
	return p
}

// SHAKE parameter sets
var (
	ParamsSHAKE128f = newParams("SLH-DSA-SHAKE-128f", 16, 66, 22, 6, 33, false)
	ParamsSHAKE128s = newParams("SLH-DSA-SHAKE-128s", 16, 63, 7, 12, 14, false)
	ParamsSHAKE192f = newParams("SLH-DSA-SHAKE-192f", 24, 66, 22, 8, 33, false)
	ParamsSHAKE192s = newParams("SLH-DSA-SHAKE-192s", 24, 63, 7, 14, 17, false)
	ParamsSHAKE256f = newParams("SLH-DSA-SHAKE-256f", 32, 68, 17, 9, 35, false)
	ParamsSHAKE256s = newParams("SLH-DSA-SHAKE-256s", 32, 64, 8, 14, 22, false)
)

// SHA2 parameter sets (identical structural params to SHAKE counterparts)
var (
	ParamsSHA2128f = newParams("SLH-DSA-SHA2-128f", 16, 66, 22, 6, 33, true)
	ParamsSHA2128s = newParams("SLH-DSA-SHA2-128s", 16, 63, 7, 12, 14, true)
	ParamsSHA2192f = newParams("SLH-DSA-SHA2-192f", 24, 66, 22, 8, 33, true)
	ParamsSHA2192s = newParams("SLH-DSA-SHA2-192s", 24, 63, 7, 14, 17, true)
	ParamsSHA2256f = newParams("SLH-DSA-SHA2-256f", 32, 68, 17, 9, 35, true)
	ParamsSHA2256s = newParams("SLH-DSA-SHA2-256s", 32, 64, 8, 14, 22, true)
)

// AllParams returns all 12 parameter sets.
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
