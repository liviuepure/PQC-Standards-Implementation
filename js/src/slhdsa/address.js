/**
 * ADRS (Address) structure for SLH-DSA (FIPS 205, Section 4.2)
 *
 * A 32-byte address used to domain-separate hash calls.
 * Fields are packed into a 32-byte buffer with specific byte offsets.
 *
 * Layout (byte offsets):
 *   [0..3]   layerAddress
 *   [4..15]  treeAddress (8 bytes used, padded)
 *   [16..19] type
 *   [20..31] type-specific fields (3 x 4-byte words)
 *
 * Address types:
 *   0 = WOTS_HASH
 *   1 = WOTS_PK
 *   2 = TREE
 *   3 = FORS_TREE
 *   4 = FORS_ROOTS
 *   5 = WOTS_PRF
 *   6 = FORS_PRF
 */

const ADDR_TYPE = {
  WOTS_HASH: 0,
  WOTS_PK: 1,
  TREE: 2,
  FORS_TREE: 3,
  FORS_ROOTS: 4,
  WOTS_PRF: 5,
  FORS_PRF: 6,
};

class ADRS {
  constructor() {
    this.data = new Uint8Array(32);
  }

  copy() {
    const a = new ADRS();
    a.data.set(this.data);
    return a;
  }

  bytes() {
    return this.data;
  }

  // --- Layer address (bytes 0-3) ---
  setLayerAddress(layer) {
    this._setWord(0, layer);
    return this;
  }

  getLayerAddress() {
    return this._getWord(0);
  }

  // --- Tree address (bytes 4-15, uses 12 bytes for up to 96-bit tree index) ---
  setTreeAddress(tree) {
    // tree can be a BigInt or Number
    // Store as big-endian in bytes 4..15 (12 bytes)
    const t = BigInt(tree);
    for (let i = 15; i >= 4; i--) {
      this.data[i] = Number(t >> BigInt((15 - i) * 8) & 0xFFn);
    }
    return this;
  }

  getTreeAddress() {
    let val = 0n;
    for (let i = 4; i <= 15; i++) {
      val = (val << 8n) | BigInt(this.data[i]);
    }
    return val;
  }

  // --- Type (bytes 16-19) ---
  setType(type) {
    this._setWord(16, type);
    // Clear type-specific bytes when type changes (per spec)
    for (let i = 20; i < 32; i++) this.data[i] = 0;
    return this;
  }

  getType() {
    return this._getWord(16);
  }

  // --- Type-specific word 1 (bytes 20-23): keypairAddress ---
  setKeyPairAddress(kp) {
    this._setWord(20, kp);
    return this;
  }

  getKeyPairAddress() {
    return this._getWord(20);
  }

  // --- Type-specific word 2 (bytes 24-27): chainAddress or treeHeight ---
  setChainAddress(chain) {
    this._setWord(24, chain);
    return this;
  }

  getChainAddress() {
    return this._getWord(24);
  }

  setTreeHeight(height) {
    this._setWord(24, height);
    return this;
  }

  getTreeHeight() {
    return this._getWord(24);
  }

  // --- Type-specific word 3 (bytes 28-31): hashAddress or treeIndex ---
  setHashAddress(hash) {
    this._setWord(28, hash);
    return this;
  }

  getHashAddress() {
    return this._getWord(28);
  }

  setTreeIndex(idx) {
    this._setWord(28, idx);
    return this;
  }

  getTreeIndex() {
    return this._getWord(28);
  }

  // --- Internal helpers ---
  _setWord(offset, value) {
    const v = value >>> 0; // ensure uint32
    this.data[offset] = (v >> 24) & 0xff;
    this.data[offset + 1] = (v >> 16) & 0xff;
    this.data[offset + 2] = (v >> 8) & 0xff;
    this.data[offset + 3] = v & 0xff;
  }

  _getWord(offset) {
    return (
      ((this.data[offset] << 24) |
        (this.data[offset + 1] << 16) |
        (this.data[offset + 2] << 8) |
        this.data[offset + 3]) >>>
      0
    );
  }
}

export { ADRS, ADDR_TYPE };
