package slhdsa

import "encoding/binary"

// Address type constants per FIPS 205.
const (
	AddrWotsHash  = 0
	AddrWotsPK    = 1
	AddrTree      = 2
	AddrForsTree  = 3
	AddrForsRoots = 4
	AddrWotsPRF   = 5
	AddrForsPRF   = 6
)

// Address is a 32-byte structure used throughout SLH-DSA.
// Layout (8 uint32 words):
//
//	Word 0:    layer address
//	Word 1-2:  tree address (64-bit, big-endian across words 1-2)
//	Word 3:    type
//	Word 4:    keypair address (or tree index for FORS/XMSS)
//	Word 5:    chain address (or tree height)
//	Word 6:    hash address (or tree index within level)
//	Word 7:    (padding/unused in some contexts)
type Address [32]byte

func (a *Address) setWord(idx int, val uint32) {
	binary.BigEndian.PutUint32(a[idx*4:], val)
}

func (a *Address) getWord(idx int) uint32 {
	return binary.BigEndian.Uint32(a[idx*4:])
}

// SetLayerAddress sets word 0.
func (a *Address) SetLayerAddress(v uint32) {
	a.setWord(0, v)
}

// GetLayerAddress returns word 0.
func (a *Address) GetLayerAddress() uint32 {
	return a.getWord(0)
}

// SetTreeAddress sets the 64-bit tree address (words 1-2).
func (a *Address) SetTreeAddress(v uint64) {
	binary.BigEndian.PutUint64(a[4:12], v)
}

// GetTreeAddress returns the 64-bit tree address.
func (a *Address) GetTreeAddress() uint64 {
	return binary.BigEndian.Uint64(a[4:12])
}

// SetType sets word 3 and zeroes words 4-7.
func (a *Address) SetType(v uint32) {
	a.setWord(3, v)
	// Zero words 4 through 7 on type change
	a.setWord(4, 0)
	a.setWord(5, 0)
	a.setWord(6, 0)
	a.setWord(7, 0)
}

// GetType returns word 3.
func (a *Address) GetType() uint32 {
	return a.getWord(3)
}

// SetKeyPairAddress sets word 4.
func (a *Address) SetKeyPairAddress(v uint32) {
	a.setWord(4, v)
}

// GetKeyPairAddress returns word 4.
func (a *Address) GetKeyPairAddress() uint32 {
	return a.getWord(4)
}

// SetChainAddress sets word 5.
func (a *Address) SetChainAddress(v uint32) {
	a.setWord(5, v)
}

// GetChainAddress returns word 5.
func (a *Address) GetChainAddress() uint32 {
	return a.getWord(5)
}

// SetHashAddress sets word 6.
func (a *Address) SetHashAddress(v uint32) {
	a.setWord(6, v)
}

// GetHashAddress returns word 6.
func (a *Address) GetHashAddress() uint32 {
	return a.getWord(6)
}

// SetTreeHeight sets word 5 (alias for tree contexts).
func (a *Address) SetTreeHeight(v uint32) {
	a.setWord(5, v)
}

// GetTreeHeight returns word 5.
func (a *Address) GetTreeHeight() uint32 {
	return a.getWord(5)
}

// SetTreeIndex sets word 6 (alias for tree contexts).
func (a *Address) SetTreeIndex(v uint32) {
	a.setWord(6, v)
}

// GetTreeIndex returns word 6.
func (a *Address) GetTreeIndex() uint32 {
	return a.getWord(6)
}

// Copy returns a copy of the address.
func (a *Address) Copy() Address {
	var c Address
	copy(c[:], a[:])
	return c
}

// CompressedAddress returns the 22-byte compressed address (ADRSc) used
// in SHA2 variants. It drops the first 3 bytes of each 4-byte word for
// words 0, 3, 4, 5, 6, 7 (keeping byte index 3 of each), and keeps
// 8 bytes for tree address.
func (a *Address) CompressedAddress() []byte {
	// ADRSc layout (22 bytes):
	// byte 0: layer (word 0, byte 3)
	// bytes 1-8: tree address (words 1-2, all 8 bytes)
	// byte 9: type (word 3, byte 3)
	// bytes 10-13: key pair (word 4, all 4 bytes)
	// bytes 14-17: chain/tree height (word 5, all 4 bytes)
	// bytes 18-21: hash/tree index (word 6, all 4 bytes)
	c := make([]byte, 22)
	c[0] = a[3]          // layer: last byte of word 0
	copy(c[1:9], a[4:12]) // tree address: words 1-2
	c[9] = a[15]          // type: last byte of word 3
	copy(c[10:14], a[16:20]) // key pair: word 4
	copy(c[14:18], a[20:24]) // chain/height: word 5
	copy(c[18:22], a[24:28]) // hash/index: word 6
	return c
}
