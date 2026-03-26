package slhdsa

// XMSS implementation per FIPS 205.

// XMSSNode computes the root of a Merkle subtree.
// FIPS 205 Algorithm 9: xmss_node(SK.seed, i, z, PK.seed, ADRS).
// Computes the node at height z and index i.
func XMSSNode(hs HashSuite, skSeed, pkSeed []byte, i, z int, adrs *Address, p *Params) []byte {
	n := p.N

	if z == 0 {
		// Leaf node: generate WOTS+ public key
		adrs.SetType(AddrWotsHash)
		adrs.SetKeyPairAddress(uint32(i))
		return WotsPKGen(hs, skSeed, pkSeed, adrs, p)
	}

	// Recursively compute left and right children
	left := XMSSNode(hs, skSeed, pkSeed, 2*i, z-1, adrs, p)
	right := XMSSNode(hs, skSeed, pkSeed, 2*i+1, z-1, adrs, p)

	adrs.SetType(AddrTree)
	adrs.SetTreeHeight(uint32(z))
	adrs.SetTreeIndex(uint32(i))

	concat := make([]byte, 0, 2*n)
	concat = append(concat, left...)
	concat = append(concat, right...)
	return hs.H(pkSeed, adrs, concat, n)
}

// XMSSSign generates an XMSS signature for a message.
// FIPS 205 Algorithm 10: xmss_sign(M, SK.seed, idx, PK.seed, ADRS).
// Returns WOTS+ sig || auth path.
func XMSSSign(hs HashSuite, msg, skSeed, pkSeed []byte, idx int, adrs *Address, p *Params) []byte {
	n := p.N

	// Generate WOTS+ signature
	adrs.SetType(AddrWotsHash)
	adrs.SetKeyPairAddress(uint32(idx))
	sig := WotsSign(hs, msg, skSeed, pkSeed, adrs, p)

	// Compute authentication path
	auth := make([]byte, 0, p.HP*n)
	for j := 0; j < p.HP; j++ {
		// sibling index at height j
		k := (idx >> uint(j)) ^ 1
		auth = append(auth, XMSSNode(hs, skSeed, pkSeed, k, j, adrs, p)...)
	}

	result := make([]byte, 0, len(sig)+len(auth))
	result = append(result, sig...)
	result = append(result, auth...)
	return result
}

// XMSSPKFromSig computes the XMSS public key from a signature.
// FIPS 205 Algorithm 11: xmss_pkFromSig(idx, SIG_XMSS, M, PK.seed, ADRS).
func XMSSPKFromSig(hs HashSuite, idx int, sigXMSS, msg, pkSeed []byte, adrs *Address, p *Params) []byte {
	n := p.N

	// Extract WOTS+ sig and auth path
	wotsSig := sigXMSS[:p.Len*n]
	auth := sigXMSS[p.Len*n:]

	// Compute WOTS+ pk from sig
	adrs.SetType(AddrWotsHash)
	adrs.SetKeyPairAddress(uint32(idx))
	node := WotsPKFromSig(hs, wotsSig, msg, pkSeed, adrs, p)

	adrs.SetType(AddrTree)
	adrs.SetTreeIndex(uint32(idx))
	for k := 0; k < p.HP; k++ {
		adrs.SetTreeHeight(uint32(k + 1))
		authK := auth[k*n : (k+1)*n]
		if (idx>>uint(k))%2 == 0 {
			adrs.SetTreeIndex(uint32(idx>>uint(k+1)))
			concat := make([]byte, 0, 2*n)
			concat = append(concat, node...)
			concat = append(concat, authK...)
			node = hs.H(pkSeed, adrs, concat, n)
		} else {
			adrs.SetTreeIndex(uint32(idx>>uint(k+1)))
			concat := make([]byte, 0, 2*n)
			concat = append(concat, authK...)
			concat = append(concat, node...)
			node = hs.H(pkSeed, adrs, concat, n)
		}
	}

	return node
}
