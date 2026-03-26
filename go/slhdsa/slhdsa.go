// Package slhdsa implements SLH-DSA (FIPS 205), a stateless hash-based
// digital signature scheme.
package slhdsa

import (
	"crypto/rand"

	"github.com/baron-chain/PQC-Standards-Implementation/go/internal/slhdsa"
)

// Re-export parameter sets for convenience.
var (
	ParamsSHAKE128f = slhdsa.ParamsSHAKE128f
	ParamsSHAKE128s = slhdsa.ParamsSHAKE128s
	ParamsSHAKE192f = slhdsa.ParamsSHAKE192f
	ParamsSHAKE192s = slhdsa.ParamsSHAKE192s
	ParamsSHAKE256f = slhdsa.ParamsSHAKE256f
	ParamsSHAKE256s = slhdsa.ParamsSHAKE256s
	ParamsSHA2128f  = slhdsa.ParamsSHA2128f
	ParamsSHA2128s  = slhdsa.ParamsSHA2128s
	ParamsSHA2192f  = slhdsa.ParamsSHA2192f
	ParamsSHA2192s  = slhdsa.ParamsSHA2192s
	ParamsSHA2256f  = slhdsa.ParamsSHA2256f
	ParamsSHA2256s  = slhdsa.ParamsSHA2256s
)

// Params is a re-export of the internal Params type.
type Params = slhdsa.Params

// KeyGen generates an SLH-DSA key pair.
// Returns (public key, secret key).
// FIPS 205 Algorithm 18: slh_keygen().
func KeyGen(params *Params) (pk, sk []byte) {
	n := params.N
	hs := slhdsa.NewHashSuite(params)

	skSeed := make([]byte, n)
	skPrf := make([]byte, n)
	pkSeed := make([]byte, n)

	if _, err := rand.Read(skSeed); err != nil {
		panic("slhdsa: crypto/rand failed: " + err.Error())
	}
	if _, err := rand.Read(skPrf); err != nil {
		panic("slhdsa: crypto/rand failed: " + err.Error())
	}
	if _, err := rand.Read(pkSeed); err != nil {
		panic("slhdsa: crypto/rand failed: " + err.Error())
	}

	// Compute root of the top-level XMSS tree in the hypertree
	var adrs slhdsa.Address
	adrs.SetLayerAddress(uint32(params.D - 1))
	pkRoot := slhdsa.XMSSNode(hs, skSeed, pkSeed, 0, params.HP, &adrs, params)

	// PK = PKseed || PKroot
	pk = make([]byte, 0, params.PKLen)
	pk = append(pk, pkSeed...)
	pk = append(pk, pkRoot...)

	// SK = SKseed || SKprf || PKseed || PKroot
	sk = make([]byte, 0, params.SKLen)
	sk = append(sk, skSeed...)
	sk = append(sk, skPrf...)
	sk = append(sk, pkSeed...)
	sk = append(sk, pkRoot...)

	return pk, sk
}

// Sign generates an SLH-DSA signature.
// FIPS 205 Algorithm 19: slh_sign(M, SK).
func Sign(sk, msg []byte, params *Params) []byte {
	n := params.N
	hs := slhdsa.NewHashSuite(params)

	// Parse SK
	skSeed := sk[:n]
	skPrf := sk[n : 2*n]
	pkSeed := sk[2*n : 3*n]
	pkRoot := sk[3*n : 4*n]

	// Generate randomizer
	optRand := make([]byte, n)
	if _, err := rand.Read(optRand); err != nil {
		panic("slhdsa: crypto/rand failed: " + err.Error())
	}

	// R = PRFmsg(SKprf, OptRand, M)
	r := hs.PRFMsg(skPrf, optRand, msg, n)

	sig := make([]byte, 0, params.SigLen)
	sig = append(sig, r...)

	// Compute message digest
	// digest = HMsg(R, PKseed, PKroot, M)
	// The digest length needs to provide:
	//   md: k*a bits = ceil(k*a/8) bytes
	//   idx_tree: h - h/d bits
	//   idx_leaf: h/d bits
	mdLen := (params.K*params.A + 7) / 8
	treeIdxBits := params.H - params.HP
	leafIdxBits := params.HP
	totalBits := treeIdxBits + leafIdxBits
	idxLen := (totalBits + 7) / 8
	digestLen := mdLen + idxLen

	digest := hs.HMsg(r, pkSeed, pkRoot, msg, digestLen)

	md := digest[:mdLen]
	idxBytes := digest[mdLen:]

	// Extract tree index and leaf index
	idxBits := base2bIdx(idxBytes, treeIdxBits, leafIdxBits)
	idxTree := idxBits.tree
	idxLeaf := idxBits.leaf

	// FORS signature
	var adrs slhdsa.Address
	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(idxTree)
	adrs.SetType(slhdsa.AddrForsTree)
	adrs.SetKeyPairAddress(uint32(idxLeaf))

	forsSig := slhdsa.FORSSign(hs, md, skSeed, pkSeed, &adrs, params)
	sig = append(sig, forsSig...)

	// Compute FORS public key
	forsPK := slhdsa.FORSPKFromSig(hs, forsSig, md, pkSeed, &adrs, params)

	// Hypertree signature
	htSig := slhdsa.HTSign(hs, forsPK, skSeed, pkSeed, idxTree, int(idxLeaf), params)
	sig = append(sig, htSig...)

	return sig
}

// Verify verifies an SLH-DSA signature.
// FIPS 205 Algorithm 20: slh_verify(M, SIG, PK).
func Verify(pk, msg, sig []byte, params *Params) bool {
	n := params.N
	hs := slhdsa.NewHashSuite(params)

	if len(sig) != params.SigLen {
		return false
	}
	if len(pk) != params.PKLen {
		return false
	}

	// Parse PK
	pkSeed := pk[:n]
	pkRoot := pk[n : 2*n]

	// Parse signature
	r := sig[:n]
	offset := n

	forsLen := params.K * (1 + params.A) * n
	forsSig := sig[offset : offset+forsLen]
	offset += forsLen

	htSig := sig[offset:]

	// Compute message digest
	mdLen := (params.K*params.A + 7) / 8
	treeIdxBits := params.H - params.HP
	leafIdxBits := params.HP
	totalBits := treeIdxBits + leafIdxBits
	idxLen := (totalBits + 7) / 8
	digestLen := mdLen + idxLen

	digest := hs.HMsg(r, pkSeed, pkRoot, msg, digestLen)

	md := digest[:mdLen]
	idxBytes := digest[mdLen:]

	idxBits := base2bIdx(idxBytes, treeIdxBits, leafIdxBits)
	idxTree := idxBits.tree
	idxLeaf := idxBits.leaf

	// Recompute FORS public key
	var adrs slhdsa.Address
	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(idxTree)
	adrs.SetType(slhdsa.AddrForsTree)
	adrs.SetKeyPairAddress(uint32(idxLeaf))

	forsPK := slhdsa.FORSPKFromSig(hs, forsSig, md, pkSeed, &adrs, params)

	// Verify hypertree signature
	return slhdsa.HTVerify(hs, forsPK, htSig, pkSeed, idxTree, int(idxLeaf), pkRoot, params)
}

// idxPair holds the tree and leaf indices extracted from the digest.
type idxPair struct {
	tree uint64
	leaf uint32
}

// base2bIdx extracts tree and leaf indices from index bytes.
func base2bIdx(idxBytes []byte, treeBits, leafBits int) idxPair {
	// Convert all bytes to a big integer
	totalBits := treeBits + leafBits
	totalBytes := (totalBits + 7) / 8

	// Ensure we have enough bytes
	data := make([]byte, totalBytes)
	if len(idxBytes) >= totalBytes {
		copy(data, idxBytes[:totalBytes])
	} else {
		copy(data[totalBytes-len(idxBytes):], idxBytes)
	}

	// Convert to big integer
	var val uint64
	for _, b := range data {
		val = (val << 8) | uint64(b)
	}

	// Mask to totalBits
	if totalBits < 64 {
		val &= (1 << uint(totalBits)) - 1
	}

	leaf := uint32(val & ((1 << uint(leafBits)) - 1))
	tree := val >> uint(leafBits)

	// Mask tree to treeBits
	if treeBits < 64 {
		tree &= (1 << uint(treeBits)) - 1
	}

	return idxPair{tree: tree, leaf: leaf}
}
