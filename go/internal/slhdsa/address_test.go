package slhdsa

import "testing"

func TestAddressSetGetLayer(t *testing.T) {
	var a Address
	a.SetLayerAddress(5)
	if got := a.GetLayerAddress(); got != 5 {
		t.Errorf("GetLayerAddress() = %d, want 5", got)
	}
}

func TestAddressSetGetTree(t *testing.T) {
	var a Address
	a.SetTreeAddress(0x123456789ABCDEF0)
	if got := a.GetTreeAddress(); got != 0x123456789ABCDEF0 {
		t.Errorf("GetTreeAddress() = %x, want 0x123456789ABCDEF0", got)
	}
}

func TestAddressTypeZeroesWords(t *testing.T) {
	var a Address
	a.SetKeyPairAddress(42)
	a.SetChainAddress(99)
	a.SetHashAddress(7)

	// Setting type should zero words 4-7
	a.SetType(AddrWotsHash)

	if got := a.GetKeyPairAddress(); got != 0 {
		t.Errorf("after SetType, GetKeyPairAddress() = %d, want 0", got)
	}
	if got := a.GetChainAddress(); got != 0 {
		t.Errorf("after SetType, GetChainAddress() = %d, want 0", got)
	}
	if got := a.GetHashAddress(); got != 0 {
		t.Errorf("after SetType, GetHashAddress() = %d, want 0", got)
	}
	if got := a.GetType(); got != AddrWotsHash {
		t.Errorf("GetType() = %d, want %d", got, AddrWotsHash)
	}
}

func TestAddressKeyPairChainHash(t *testing.T) {
	var a Address
	a.SetKeyPairAddress(100)
	a.SetChainAddress(200)
	a.SetHashAddress(300)

	if got := a.GetKeyPairAddress(); got != 100 {
		t.Errorf("GetKeyPairAddress() = %d, want 100", got)
	}
	if got := a.GetChainAddress(); got != 200 {
		t.Errorf("GetChainAddress() = %d, want 200", got)
	}
	if got := a.GetHashAddress(); got != 300 {
		t.Errorf("GetHashAddress() = %d, want 300", got)
	}
}

func TestAddressTreeHeightIndex(t *testing.T) {
	var a Address
	a.SetTreeHeight(10)
	a.SetTreeIndex(20)

	if got := a.GetTreeHeight(); got != 10 {
		t.Errorf("GetTreeHeight() = %d, want 10", got)
	}
	if got := a.GetTreeIndex(); got != 20 {
		t.Errorf("GetTreeIndex() = %d, want 20", got)
	}
}

func TestAddressCopy(t *testing.T) {
	var a Address
	a.SetLayerAddress(3)
	a.SetTreeAddress(0xFF)
	a.SetType(AddrForsTree)
	a.SetKeyPairAddress(77)

	b := a.Copy()
	if b != a {
		t.Error("Copy should produce identical address")
	}

	// Modify original, copy should be unchanged
	a.SetLayerAddress(99)
	if b.GetLayerAddress() == 99 {
		t.Error("Copy should be independent of original")
	}
}

func TestCompressedAddress(t *testing.T) {
	var a Address
	a.SetLayerAddress(1)
	a.SetTreeAddress(0x0203040506070809)
	a.SetType(2)
	a.SetKeyPairAddress(0x0A0B0C0D)
	a.SetChainAddress(0x0E0F1011)
	a.SetHashAddress(0x12131415)

	c := a.CompressedAddress()
	if len(c) != 22 {
		t.Fatalf("CompressedAddress length = %d, want 22", len(c))
	}

	// byte 0: layer (byte 3 of word 0) = 1
	if c[0] != 1 {
		t.Errorf("ADRSc[0] = %d, want 1", c[0])
	}
	// byte 9: type (byte 3 of word 3) = 2
	if c[9] != 2 {
		t.Errorf("ADRSc[9] = %d, want 2", c[9])
	}
}

func TestAllAddressTypes(t *testing.T) {
	types := []uint32{
		AddrWotsHash, AddrWotsPK, AddrTree,
		AddrForsTree, AddrForsRoots, AddrWotsPRF, AddrForsPRF,
	}
	expected := []uint32{0, 1, 2, 3, 4, 5, 6}

	for i, typ := range types {
		if typ != expected[i] {
			t.Errorf("Address type constant %d = %d, want %d", i, typ, expected[i])
		}
	}
}
