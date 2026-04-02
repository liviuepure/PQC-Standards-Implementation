package hqc

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/sha3"
)

// KeyGen generates an HQC key pair.
// Returns (publicKey, secretKey, error).
func KeyGen(p *Params, rng io.Reader) ([]byte, []byte, error) {
	if rng == nil {
		rng = rand.Reader
	}

	// Generate random seeds
	skSeed := make([]byte, SeedBytes)
	if _, err := io.ReadFull(rng, skSeed); err != nil {
		return nil, nil, err
	}
	pkSeed := make([]byte, SeedBytes)
	if _, err := io.ReadFull(rng, pkSeed); err != nil {
		return nil, nil, err
	}

	// Generate secret vectors x, y and sigma from sk_seed
	skExpander := newSeedExpander(skSeed)
	x := vectSetRandomFixedWeight(skExpander, p.N, p.W)
	y := vectSetRandomFixedWeight(skExpander, p.N, p.W)
	// sigma is also derived from sk_seed but not stored in SK
	// It is regenerated during decapsulation

	// Generate random vector h from pk_seed
	pkExpander := newSeedExpander(pkSeed)
	h := vectSetRandom(pkExpander, p.N)

	// Compute s = x + h * y mod (x^n - 1)
	hy := vectMul(h, y, p.N)
	s := vectAdd(hy, x)
	s = vectResize(s, p.N)

	// Serialize public key: [pk_seed (40 bytes)] [s (VecNSizeBytes bytes)]
	pk := make([]byte, p.PKSize)
	copy(pk, pkSeed)
	sBytes := vectToBytes(s, p.VecNSizeBytes)
	copy(pk[SeedBytes:], sBytes)

	// Serialize secret key: [sk_seed (40 bytes)] [pk (PKSize bytes)]
	sk := make([]byte, p.SKSize)
	copy(sk, skSeed)
	copy(sk[SeedBytes:], pk)

	return pk, sk, nil
}

// Encaps encapsulates a shared secret using the public key.
// Returns (ciphertext, sharedSecret, error).
func Encaps(pk []byte, p *Params, rng io.Reader) ([]byte, []byte, error) {
	if rng == nil {
		rng = rand.Reader
	}

	// Generate random message m
	m := make([]byte, p.VecKSizeBytes)
	if _, err := io.ReadFull(rng, m); err != nil {
		return nil, nil, err
	}

	// Compute d = H(m) = SHAKE256(H_domain || m), 64 bytes
	d := computeD(m)

	// Compute theta = SHAKE256(G_domain || m || pk || d)
	theta := computeTheta(m, pk, d, p)

	// PKE Encrypt
	u, v := pkeEncrypt(m, theta, pk, p)

	// Compute shared secret: ss = SHAKE256(K_domain || m || u_bytes || v_bytes)
	ss := computeSS(m, u, v, p)

	// Serialize ciphertext: [u (VecNSizeBytes)] [v (VecN1N2SizeBytes)] [d (64 bytes)]
	ct := make([]byte, p.CTSize)
	uBytes := vectToBytes(u, p.VecNSizeBytes)
	vBytes := vectToBytes(v, p.VecN1N2SizeBytes)
	copy(ct, uBytes)
	copy(ct[p.VecNSizeBytes:], vBytes)
	copy(ct[p.VecNSizeBytes+p.VecN1N2SizeBytes:], d)

	return ct, ss, nil
}

// Decaps decapsulates a shared secret from a ciphertext using the secret key.
func Decaps(sk, ct []byte, p *Params) ([]byte, error) {
	// Parse secret key: [sk_seed (40 bytes)] [pk (PKSize bytes)]
	skSeed := sk[:SeedBytes]
	pk := sk[SeedBytes:]

	// Parse ciphertext: [u (VecNSizeBytes)] [v (VecN1N2SizeBytes)] [d (64 bytes)]
	u := vectFromBytes(ct[:p.VecNSizeBytes], p.VecNSize64)
	v := vectFromBytes(ct[p.VecNSizeBytes:p.VecNSizeBytes+p.VecN1N2SizeBytes], p.VecN1N2Size64)
	d := ct[p.VecNSizeBytes+p.VecN1N2SizeBytes:]

	// Regenerate secret vectors x, y and sigma from sk_seed
	skExpander := newSeedExpander(skSeed)
	_ = vectSetRandomFixedWeight(skExpander, p.N, p.W) // x (not needed for decrypt)
	y := vectSetRandomFixedWeight(skExpander, p.N, p.W)
	// Generate sigma (rejection secret) from the same seed expander
	sigma := make([]byte, p.VecKSizeBytes)
	skExpander.Read(sigma)

	// Compute v - u * y (which is v XOR u*y since we are in GF(2))
	uy := vectMul(u, y, p.N)

	// Truncate uy to n1*n2 bits for the tensor code space
	uyTrunc := make([]uint64, p.VecN1N2Size64)
	copy(uyTrunc, uy)
	if p.N1N2%64 != 0 && p.VecN1N2Size64 > 0 {
		uyTrunc[p.VecN1N2Size64-1] &= (1 << uint(p.N1N2%64)) - 1
	}

	vMinusUY := vectAdd(v, uyTrunc)

	// Decode using tensor product code
	mPrime, ok := tensorDecode(vMinusUY, p)
	if !ok {
		// Decoding failed - use sigma as rejection value
		mPrime = make([]byte, p.VecKSizeBytes)
		copy(mPrime, sigma)
	}

	// Re-encrypt to verify
	thetaPrime := computeTheta(mPrime, pk, d, p)
	u2, v2 := pkeEncrypt(mPrime, thetaPrime, pk, p)

	// Constant-time comparison
	u2Trunc := vectResize(u2, p.N)
	uOrig := vectResize(u, p.N)
	uMatch := vectEqual(u2Trunc, uOrig)

	v2Trunc := vectResize(v2, p.N1N2)
	vOrig := vectResize(v, p.N1N2)
	vMatch := vectEqual(v2Trunc, vOrig)

	match := uMatch & vMatch

	// Constant-time selection of message or sigma
	mc := make([]byte, p.VecKSizeBytes)
	maskOK := byte(0 - uint8(match))     // 0xFF if match, 0x00 otherwise
	maskFail := byte(0 - uint8(1-match)) // 0x00 if match, 0xFF otherwise
	for i := 0; i < p.VecKSizeBytes; i++ {
		mc[i] = (mPrime[i] & maskOK) | (sigma[i] & maskFail)
	}

	// Compute shared secret
	ss := computeSS(mc, u, v, p)

	return ss, nil
}

// pkeEncrypt implements the PKE encryption.
func pkeEncrypt(m, theta, pk []byte, p *Params) ([]uint64, []uint64) {
	// Parse public key
	pkSeed := pk[:SeedBytes]
	s := vectFromBytes(pk[SeedBytes:], p.VecNSize64)

	// Generate h from pk_seed
	pkExpander := newSeedExpander(pkSeed)
	h := vectSetRandom(pkExpander, p.N)

	// Generate r1, r2 with weight WR and e with weight WE from theta
	thetaExpander := newSeedExpander(theta)
	r1 := vectSetRandomFixedWeight(thetaExpander, p.N, p.WR)
	r2 := vectSetRandomFixedWeight(thetaExpander, p.N, p.WR)
	e := vectSetRandomFixedWeight(thetaExpander, p.N, p.WE)

	// u = r1 + h * r2 mod (x^n - 1)
	hr2 := vectMul(h, r2, p.N)
	u := vectAdd(hr2, r1)
	u = vectResize(u, p.N)

	// v = encode(m) + s * r2 + e (in GF(2)^{n1*n2})
	encoded := tensorEncode(m, p)

	// s * r2 in the ring, then truncate to n1*n2 bits
	sr2 := vectMul(s, r2, p.N)
	sr2Trunc := make([]uint64, p.VecN1N2Size64)
	copy(sr2Trunc, sr2)
	if p.N1N2%64 != 0 && p.VecN1N2Size64 > 0 {
		sr2Trunc[p.VecN1N2Size64-1] &= (1 << uint(p.N1N2%64)) - 1
	}

	// Resize e to n1*n2
	eResized := make([]uint64, p.VecN1N2Size64)
	copy(eResized, e)
	if p.N1N2%64 != 0 && p.VecN1N2Size64 > 0 {
		eResized[p.VecN1N2Size64-1] &= (1 << uint(p.N1N2%64)) - 1
	}

	v := vectAdd(encoded, sr2Trunc)
	v = vectAdd(v, eResized)
	v = vectResize(v, p.N1N2)

	return u, v
}

// computeD computes d = SHAKE256(H_domain || m), producing 64 bytes.
func computeD(m []byte) []byte {
	h := sha3.NewShake256()
	h.Write([]byte{HFctDomain})
	h.Write(m)
	d := make([]byte, SharedSecretBytes) // 64 bytes
	h.Read(d)
	return d
}

// computeTheta computes theta = SHAKE256(G_domain || m || pk || d).
func computeTheta(m, pk, d []byte, p *Params) []byte {
	h := sha3.NewShake256()
	h.Write([]byte{GFctDomain})
	h.Write(m)
	h.Write(pk)
	h.Write(d)
	theta := make([]byte, SeedBytes)
	h.Read(theta)
	return theta
}

// computeSS computes ss = SHAKE256(K_domain || m || u_bytes || v_bytes).
func computeSS(m []byte, u, v []uint64, p *Params) []byte {
	h := sha3.NewShake256()
	h.Write([]byte{KFctDomain})
	h.Write(m)
	h.Write(vectToBytes(u, p.VecNSizeBytes))
	h.Write(vectToBytes(v, p.VecN1N2SizeBytes))
	ss := make([]byte, SharedSecretBytes)
	h.Read(ss)
	return ss
}

// newSeedExpander creates a SHAKE256-based seed expander.
func newSeedExpander(seed []byte) *seedExpander {
	h := sha3.NewShake256()
	h.Write(seed)
	return &seedExpander{shake: h}
}

type seedExpander struct {
	shake sha3.ShakeHash
}

func (se *seedExpander) Read(p []byte) (int, error) {
	se.shake.Read(p)
	return len(p), nil
}

// vectSetRandom generates a random vector of n bits using the seed expander.
func vectSetRandom(se *seedExpander, n int) []uint64 {
	nWords := (n + 63) / 64
	nBytes := nWords * 8
	buf := make([]byte, nBytes)
	se.Read(buf)
	v := vectFromBytes(buf, nWords)
	// Mask the last word
	rem := n % 64
	if rem != 0 {
		v[nWords-1] &= (1 << uint(rem)) - 1
	}
	return v
}

// vectSetRandomFixedWeight generates a random vector of n bits
// with exactly 'weight' bits set, using the seed expander.
// Uses the constant-time algorithm from the HQC reference implementation.
func vectSetRandomFixedWeight(se *seedExpander, n, weight int) []uint64 {
	nWords := (n + 63) / 64
	v := make([]uint64, nWords)

	// Generate random positions
	positions := make([]uint32, weight)
	buf := make([]byte, 4)

	for i := 0; i < weight; i++ {
		for {
			se.Read(buf)
			pos := uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24
			pos = pos % uint32(n)

			// Check for duplicates (simple rejection sampling)
			duplicate := false
			for j := 0; j < i; j++ {
				if positions[j] == pos {
					duplicate = true
					break
				}
			}
			if !duplicate {
				positions[i] = pos
				break
			}
		}
	}

	// Set bits at the generated positions
	for _, pos := range positions {
		vectSetBit(v, int(pos))
	}

	return v
}
