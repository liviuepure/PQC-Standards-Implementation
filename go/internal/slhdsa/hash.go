package slhdsa

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/sha3"
)

// HashSuite provides all hash functions needed by SLH-DSA.
type HashSuite interface {
	// F is a tweakable hash function: F(PKseed, ADRS, M1) -> n bytes
	F(pkSeed []byte, adrs *Address, m1 []byte, n int) []byte

	// H is a tweakable hash function: H(PKseed, ADRS, M1||M2) -> n bytes
	H(pkSeed []byte, adrs *Address, m []byte, n int) []byte

	// Tl is a tweakable hash function for longer inputs: Tl(PKseed, ADRS, M) -> n bytes
	Tl(pkSeed []byte, adrs *Address, m []byte, n int) []byte

	// PRF generates a pseudorandom n-byte value: PRF(PKseed, SKseed, ADRS) -> n bytes
	PRF(pkSeed, skSeed []byte, adrs *Address, n int) []byte

	// PRFMsg generates a pseudorandom value for message hashing.
	// PRFMsg(SKprf, optRand, M) -> n bytes
	PRFMsg(skPrf, optRand, msg []byte, n int) []byte

	// HMsg is the message hash function.
	// HMsg(R, PKseed, PKroot, M) -> m bytes (where m depends on context)
	HMsg(r, pkSeed, pkRoot, msg []byte, outLen int) []byte
}

// NewHashSuite returns the appropriate hash suite for the given params.
func NewHashSuite(p *Params) HashSuite {
	if p.IsSHA2 {
		return &sha2Hash{n: p.N}
	}
	return &shakeHash{}
}

// ---- SHAKE-based hash suite ----

type shakeHash struct{}

func (s *shakeHash) F(pkSeed []byte, adrs *Address, m1 []byte, n int) []byte {
	return s.shakeHash(pkSeed, adrs[:], m1, n)
}

func (s *shakeHash) H(pkSeed []byte, adrs *Address, m []byte, n int) []byte {
	return s.shakeHash(pkSeed, adrs[:], m, n)
}

func (s *shakeHash) Tl(pkSeed []byte, adrs *Address, m []byte, n int) []byte {
	return s.shakeHash(pkSeed, adrs[:], m, n)
}

func (s *shakeHash) PRF(pkSeed, skSeed []byte, adrs *Address, n int) []byte {
	return s.shakeHash(pkSeed, adrs[:], skSeed, n)
}

func (s *shakeHash) PRFMsg(skPrf, optRand, msg []byte, n int) []byte {
	h := sha3.NewShake256()
	h.Write(skPrf)
	h.Write(optRand)
	h.Write(msg)
	out := make([]byte, n)
	h.Read(out)
	return out
}

func (s *shakeHash) HMsg(r, pkSeed, pkRoot, msg []byte, outLen int) []byte {
	h := sha3.NewShake256()
	h.Write(r)
	h.Write(pkSeed)
	h.Write(pkRoot)
	h.Write(msg)
	out := make([]byte, outLen)
	h.Read(out)
	return out
}

// shakeHash computes SHAKE256(pkSeed || adrs || m) truncated to n bytes.
func (s *shakeHash) shakeHash(pkSeed, adrs, m []byte, n int) []byte {
	h := sha3.NewShake256()
	h.Write(pkSeed)
	h.Write(adrs)
	h.Write(m)
	out := make([]byte, n)
	h.Read(out)
	return out
}

// ---- SHA2-based hash suite ----

type sha2Hash struct {
	n int
}

// newSHA2 returns sha256 for n<=16, sha512 for n>16.
func (s *sha2Hash) newHash() hash.Hash {
	if s.n <= 16 {
		return sha256.New()
	}
	return sha512.New()
}

// hashSize returns the native hash output size.
func (s *sha2Hash) hashSize() int {
	if s.n <= 16 {
		return 32
	}
	return 64
}

// sha2Tweakable computes the SHA2 tweakable hash:
// SHA-X(PKseed || padding || ADRSc || M), truncated to n bytes.
func (s *sha2Hash) sha2Tweakable(pkSeed []byte, adrs *Address, m []byte) []byte {
	h := s.newHash()
	blockSize := h.BlockSize()
	adrsc := adrs.CompressedAddress()

	// Padding: PKseed is padded to blockSize
	padded := make([]byte, blockSize)
	copy(padded, pkSeed)

	h.Write(padded)
	h.Write(adrsc)
	h.Write(m)
	sum := h.Sum(nil)
	return sum[:s.n]
}

func (s *sha2Hash) F(pkSeed []byte, adrs *Address, m1 []byte, n int) []byte {
	return s.sha2Tweakable(pkSeed, adrs, m1)
}

func (s *sha2Hash) H(pkSeed []byte, adrs *Address, m []byte, n int) []byte {
	return s.sha2Tweakable(pkSeed, adrs, m)
}

func (s *sha2Hash) Tl(pkSeed []byte, adrs *Address, m []byte, n int) []byte {
	return s.sha2Tweakable(pkSeed, adrs, m)
}

func (s *sha2Hash) PRF(pkSeed, skSeed []byte, adrs *Address, n int) []byte {
	h := s.newHash()
	blockSize := h.BlockSize()
	adrsc := adrs.CompressedAddress()

	padded := make([]byte, blockSize)
	copy(padded, pkSeed)

	h.Write(padded)
	h.Write(adrsc)
	h.Write(skSeed)
	sum := h.Sum(nil)
	return sum[:n]
}

func (s *sha2Hash) PRFMsg(skPrf, optRand, msg []byte, n int) []byte {
	// HMAC-SHA-X(SKprf, OptRand || M), truncated to n bytes
	var mac hash.Hash
	if s.n <= 16 {
		mac = hmac.New(sha256.New, skPrf)
	} else {
		mac = hmac.New(sha512.New, skPrf)
	}
	mac.Write(optRand)
	mac.Write(msg)
	sum := mac.Sum(nil)
	return sum[:n]
}

func (s *sha2Hash) HMsg(r, pkSeed, pkRoot, msg []byte, outLen int) []byte {
	// MGF1-SHA-X(R || PKseed || SHA-X(R || PKseed || PKroot || M), outLen)
	h := s.newHash()
	h.Write(r)
	h.Write(pkSeed)
	h.Write(pkRoot)
	h.Write(msg)
	digest := h.Sum(nil)

	seed := make([]byte, 0, len(r)+len(pkSeed)+len(digest))
	seed = append(seed, r...)
	seed = append(seed, pkSeed...)
	seed = append(seed, digest...)

	return mgf1(seed, outLen, s.newHash)
}

// mgf1 implements MGF1 as defined in PKCS#1.
func mgf1(seed []byte, length int, newHash func() hash.Hash) []byte {
	var result []byte
	counter := uint32(0)
	for len(result) < length {
		h := newHash()
		h.Write(seed)
		ctr := toByte(uint64(counter), 4)
		h.Write(ctr)
		result = append(result, h.Sum(nil)...)
		counter++
	}
	return result[:length]
}
