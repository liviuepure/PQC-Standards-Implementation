// Package hqc implements the HQC (Hamming Quasi-Cyclic) KEM.
//
// HQC is a code-based key encapsulation mechanism selected by NIST for
// post-quantum cryptography standardization. It combines a quasi-cyclic
// code over GF(2), a tensor product code (Reed-Muller x Reed-Solomon)
// for error correction, and a Fujisaki-Okeyama transform for CCA security.
package hqc

// Params holds the parameter set for an HQC security level.
type Params struct {
	Name   string
	N      int // ring dimension (polynomial degree mod x^n - 1)
	N1     int // Reed-Solomon codeword length
	N2     int // Reed-Muller codeword length (duplicated)
	N1N2   int // concatenated code length in bits = N1 * N2
	K      int // message size in bytes (RS information symbols)
	Delta  int // RS error correction capability
	G      int // RS generator polynomial degree = 2*Delta + 1
	W      int // weight of secret key vectors x, y
	WR     int // weight of encryption vectors r1, r2
	WE     int // weight of ephemeral error vector e
	PKSize int // public key size in bytes
	SKSize int // secret key size in bytes
	CTSize int // ciphertext size in bytes
	SSSize int // shared secret size in bytes

	// Derived sizes (in uint64 words and bytes)
	VecNSize64   int // ceil(N / 64)
	VecNSizeBytes int // ceil(N / 8)
	VecN1N2Size64   int
	VecN1N2SizeBytes int
	VecKSizeBytes int // K bytes

	// GF(2^8) parameters
	GFPoly    uint16 // irreducible polynomial for GF(2^8)
	GFMulOrder int   // multiplicative order = 255

	// Reed-Muller parameters
	RMOrder int // RM(1, RMOrder), base codeword length = 2^RMOrder = 128
	Multiplicity int // number of repetitions: N2 / 128
}

const (
	// SeedBytes is the seed size used for key generation.
	SeedBytes = 40
	// HashBytes is the size of d = H(m) included in the ciphertext (SHAKE256 output).
	HashBytes = 64
	// SharedSecretBytes is the shared secret size (SHAKE256-512 output).
	SharedSecretBytes = 64
	// SigmaBytes equals VecKSizeBytes for the rejection secret.
	// (varies per parameter set, stored in Params.VecKSizeBytes)
)

// Domain separation bytes for SHAKE256 hashing.
const (
	GFctDomain byte = 3 // domain for theta = G(m || pk || salt)
	HFctDomain byte = 4 // domain for d = H(m)
	KFctDomain byte = 5 // domain for ss = K(m || ct)
)

// Pre-defined parameter sets per the HQC specification (PQClean reference).
var (
	// HQC128 targets NIST security level 1 (128-bit).
	HQC128 = &Params{
		Name:   "HQC-128",
		N:      17669,
		N1:     46,
		N2:     384,
		N1N2:   17664, // 46 * 384
		K:      16,
		Delta:  15,
		G:      31, // 2*15 + 1
		W:      66,
		WR:     77,
		WE:     77,
		PKSize: 2249,
		SKSize: 2289,
		CTSize: 4481,
		SSSize: SharedSecretBytes,

		VecNSize64:       277, // ceil(17669/64)
		VecNSizeBytes:    2209, // ceil(17669/8)
		VecN1N2Size64:    276, // ceil(17664/64)
		VecN1N2SizeBytes: 2208, // ceil(17664/8)
		VecKSizeBytes:    16,

		GFPoly:     0x11B,
		GFMulOrder: 255,
		RMOrder:    7,
		Multiplicity: 3, // 384 / 128
	}

	// HQC192 targets NIST security level 3 (192-bit).
	HQC192 = &Params{
		Name:   "HQC-192",
		N:      35851,
		N1:     56,
		N2:     640,
		N1N2:   35840, // 56 * 640
		K:      24,
		Delta:  16,
		G:      33, // 2*16 + 1
		W:      100,
		WR:     117,
		WE:     117,
		PKSize: 4522,
		SKSize: 4562,
		CTSize: 9026,
		SSSize: SharedSecretBytes,

		VecNSize64:       561, // ceil(35851/64)
		VecNSizeBytes:    4482, // ceil(35851/8)
		VecN1N2Size64:    560, // ceil(35840/64)
		VecN1N2SizeBytes: 4480, // ceil(35840/8)
		VecKSizeBytes:    24,

		GFPoly:     0x11B,
		GFMulOrder: 255,
		RMOrder:    7,
		Multiplicity: 5, // 640 / 128
	}

	// HQC256 targets NIST security level 5 (256-bit).
	HQC256 = &Params{
		Name:   "HQC-256",
		N:      57637,
		N1:     90,
		N2:     640,
		N1N2:   57600, // 90 * 640
		K:      32,
		Delta:  29,
		G:      59, // 2*29 + 1
		W:      131,
		WR:     153,
		WE:     153,
		PKSize: 7245,
		SKSize: 7285,
		CTSize: 14469,
		SSSize: SharedSecretBytes,

		VecNSize64:       901, // ceil(57637/64)
		VecNSizeBytes:    7205, // ceil(57637/8)
		VecN1N2Size64:    900, // ceil(57600/64)
		VecN1N2SizeBytes: 7200, // ceil(57600/8)
		VecKSizeBytes:    32,

		GFPoly:     0x11B,
		GFMulOrder: 255,
		RMOrder:    7,
		Multiplicity: 5, // 640 / 128
	}
)

// AllParams returns all supported HQC parameter sets.
func AllParams() []*Params {
	return []*Params{HQC128, HQC192, HQC256}
}
