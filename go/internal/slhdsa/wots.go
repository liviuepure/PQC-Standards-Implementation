package slhdsa

// WOTS+ implementation per FIPS 205.

// chain computes the chaining function: iterates F from step s to s+steps-1.
// FIPS 205 Algorithm 5: chain(X, i, s, PK.seed, ADRS).
func chain(hs HashSuite, x []byte, start, steps int, pkSeed []byte, adrs *Address, n int) []byte {
	if steps == 0 {
		return append([]byte{}, x...)
	}
	tmp := append([]byte{}, x...)
	for j := start; j < start+steps; j++ {
		adrs.SetHashAddress(uint32(j))
		tmp = hs.F(pkSeed, adrs, tmp, n)
	}
	return tmp
}

// WotsSign generates a WOTS+ signature.
// FIPS 205 Algorithm 6: wots_sign(M, SK.seed, PK.seed, ADRS).
func WotsSign(hs HashSuite, msg []byte, skSeed, pkSeed []byte, adrs *Address, p *Params) []byte {
	n := p.N
	w := p.W

	// Compute checksum
	msgInts := base2b(msg, 4, 2*n) // log2(w)=4 for w=16
	csum := 0
	for _, v := range msgInts {
		csum += (w - 1) - v
	}
	// csum needs ceil(len1 * log2(w) + 1 + floor(log2(len1 * (w-1))) / log2(w)) = 3 base-16 digits
	csumBytes := toByte(uint64(csum)<<4, 2) // shift left by 4 to align
	csumInts := base2b(csumBytes, 4, 3)

	allInts := append(msgInts, csumInts...)

	sig := make([]byte, 0, p.Len*n)

	// Generate WOTS+ secret key values and chain
	skAdrs := adrs.Copy()
	skAdrs.SetType(AddrWotsPRF)
	skAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress())

	for i := 0; i < p.Len; i++ {
		skAdrs.SetChainAddress(uint32(i))
		sk := hs.PRF(pkSeed, skSeed, &skAdrs, n)

		adrs.SetChainAddress(uint32(i))
		sig = append(sig, chain(hs, sk, 0, allInts[i], pkSeed, adrs, n)...)
	}

	return sig
}

// WotsPKGen generates the WOTS+ public key.
// FIPS 205 Algorithm 7 variant.
func WotsPKGen(hs HashSuite, skSeed, pkSeed []byte, adrs *Address, p *Params) []byte {
	n := p.N

	skAdrs := adrs.Copy()
	skAdrs.SetType(AddrWotsPRF)
	skAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress())

	tmp := make([]byte, 0, p.Len*n)
	for i := 0; i < p.Len; i++ {
		skAdrs.SetChainAddress(uint32(i))
		sk := hs.PRF(pkSeed, skSeed, &skAdrs, n)
		adrs.SetChainAddress(uint32(i))
		tmp = append(tmp, chain(hs, sk, 0, p.W-1, pkSeed, adrs, n)...)
	}

	pkAdrs := adrs.Copy()
	pkAdrs.SetType(AddrWotsPK)
	pkAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress())
	return hs.Tl(pkSeed, &pkAdrs, tmp, n)
}

// WotsPKFromSig computes the WOTS+ public key from a signature.
// FIPS 205 Algorithm 8: wots_pkFromSig(sig, M, PK.seed, ADRS).
func WotsPKFromSig(hs HashSuite, sig, msg, pkSeed []byte, adrs *Address, p *Params) []byte {
	n := p.N
	w := p.W

	msgInts := base2b(msg, 4, 2*n)
	csum := 0
	for _, v := range msgInts {
		csum += (w - 1) - v
	}
	csumBytes := toByte(uint64(csum)<<4, 2)
	csumInts := base2b(csumBytes, 4, 3)

	allInts := append(msgInts, csumInts...)

	tmp := make([]byte, 0, p.Len*n)
	for i := 0; i < p.Len; i++ {
		adrs.SetChainAddress(uint32(i))
		sigChunk := sig[i*n : (i+1)*n]
		tmp = append(tmp, chain(hs, sigChunk, allInts[i], (w-1)-allInts[i], pkSeed, adrs, n)...)
	}

	pkAdrs := adrs.Copy()
	pkAdrs.SetType(AddrWotsPK)
	pkAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress())
	return hs.Tl(pkSeed, &pkAdrs, tmp, n)
}
