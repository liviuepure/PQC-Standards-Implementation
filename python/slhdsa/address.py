"""ADRS (Address) structure for SLH-DSA per FIPS 205, Section 4.2."""


# Address type constants (FIPS 205, Table 2)
WOTS_HASH = 0
WOTS_PK = 1
TREE = 2
FORS_TREE = 3
FORS_ROOTS = 4
WOTS_PRF = 5
FORS_PRF = 6


class ADRS:
    """32-byte address used in SLH-DSA hash function calls.

    Layout (FIPS 205, Figure 2):
      Bytes  0..3:   layer address
      Bytes  4..15:  tree address (8 bytes, padded to 12)
      Bytes 16..19:  type
      Bytes 20..31:  type-specific fields (3 x 4 bytes)
    """

    def __init__(self):
        self._data = bytearray(32)

    def copy(self) -> "ADRS":
        a = ADRS()
        a._data = bytearray(self._data)
        return a

    def to_bytes(self) -> bytes:
        return bytes(self._data)

    # --- Layer address (bytes 0..3) ---
    def set_layer_address(self, layer: int) -> "ADRS":
        self._data[0:4] = layer.to_bytes(4, "big")
        return self

    def get_layer_address(self) -> int:
        return int.from_bytes(self._data[0:4], "big")

    # --- Tree address (bytes 4..15, 12 bytes) ---
    def set_tree_address(self, tree: int) -> "ADRS":
        self._data[4:16] = tree.to_bytes(12, "big")
        return self

    def get_tree_address(self) -> int:
        return int.from_bytes(self._data[4:16], "big")

    # --- Type (bytes 16..19) ---
    def set_type(self, addr_type: int) -> "ADRS":
        self._data[16:20] = addr_type.to_bytes(4, "big")
        # Clear type-specific fields when type changes (FIPS 205 requirement)
        self._data[20:32] = b"\x00" * 12
        return self

    def get_type(self) -> int:
        return int.from_bytes(self._data[16:20], "big")

    # --- Type-specific word 1 (bytes 20..23) ---
    def set_key_pair_address(self, kp: int) -> "ADRS":
        self._data[20:24] = kp.to_bytes(4, "big")
        return self

    def get_key_pair_address(self) -> int:
        return int.from_bytes(self._data[20:24], "big")

    # --- Type-specific word 2 (bytes 24..27) ---
    def set_chain_address(self, chain: int) -> "ADRS":
        self._data[24:28] = chain.to_bytes(4, "big")
        return self

    def set_tree_height(self, height: int) -> "ADRS":
        self._data[24:28] = height.to_bytes(4, "big")
        return self

    def get_tree_height(self) -> int:
        return int.from_bytes(self._data[24:28], "big")

    # --- Type-specific word 3 (bytes 28..31) ---
    def set_hash_address(self, h: int) -> "ADRS":
        self._data[28:32] = h.to_bytes(4, "big")
        return self

    def set_tree_index(self, idx: int) -> "ADRS":
        self._data[28:32] = idx.to_bytes(4, "big")
        return self

    def get_tree_index(self) -> int:
        return int.from_bytes(self._data[28:32], "big")
