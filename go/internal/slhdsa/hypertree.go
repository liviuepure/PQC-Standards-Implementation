package slhdsa

// Hypertree implementation per FIPS 205.

// HTSign generates a hypertree signature.
// FIPS 205 Algorithm 16: ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf).
func HTSign(hs HashSuite, msg, skSeed, pkSeed []byte, idxTree uint64, idxLeaf int, p *Params) []byte {
	var adrs Address

	// Sign at layer 0
	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(idxTree)
	sigTmp := XMSSSign(hs, msg, skSeed, pkSeed, idxLeaf, &adrs, p)
	sigHT := make([]byte, 0, p.D*(p.Len+p.HP)*p.N)
	sigHT = append(sigHT, sigTmp...)

	root := XMSSPKFromSig(hs, idxLeaf, sigTmp, msg, pkSeed, &adrs, p)

	for j := 1; j < p.D; j++ {
		idxLeaf = int(idxTree & uint64((1<<uint(p.HP))-1))
		idxTree = idxTree >> uint(p.HP)

		adrs.SetLayerAddress(uint32(j))
		adrs.SetTreeAddress(idxTree)

		sigTmp = XMSSSign(hs, root, skSeed, pkSeed, idxLeaf, &adrs, p)
		sigHT = append(sigHT, sigTmp...)

		if j < p.D-1 {
			root = XMSSPKFromSig(hs, idxLeaf, sigTmp, root, pkSeed, &adrs, p)
		}
	}

	return sigHT
}

// HTVerify verifies a hypertree signature.
// FIPS 205 Algorithm 17: ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root).
func HTVerify(hs HashSuite, msg, sigHT, pkSeed []byte, idxTree uint64, idxLeaf int, pkRoot []byte, p *Params) bool {
	var adrs Address
	n := p.N
	xmssLen := (p.Len + p.HP) * n

	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(idxTree)

	sigXMSS := sigHT[:xmssLen]
	node := XMSSPKFromSig(hs, idxLeaf, sigXMSS, msg, pkSeed, &adrs, p)

	for j := 1; j < p.D; j++ {
		idxLeaf = int(idxTree & uint64((1<<uint(p.HP))-1))
		idxTree = idxTree >> uint(p.HP)

		adrs.SetLayerAddress(uint32(j))
		adrs.SetTreeAddress(idxTree)

		sigXMSS = sigHT[j*xmssLen : (j+1)*xmssLen]
		node = XMSSPKFromSig(hs, idxLeaf, sigXMSS, node, pkSeed, &adrs, p)
	}

	// Compare with root
	if len(node) != len(pkRoot) {
		return false
	}
	for i := range node {
		if node[i] != pkRoot[i] {
			return false
		}
	}
	return true
}
