// SLH-DSA ADRS (Address) structure

public struct SlhAddress {
    public var data: [UInt8]

    // Address types
    public static let wotsHash: UInt32      = 0
    public static let wotsPk: UInt32        = 1
    public static let tree: UInt32          = 2
    public static let forsTree: UInt32      = 3
    public static let forsRoots: UInt32     = 4
    public static let wotsKeyPrf: UInt32    = 5
    public static let forsKeyPrf: UInt32    = 6

    public init() {
        data = [UInt8](repeating: 0, count: 32)
    }

    // Layer address [0..3]
    public mutating func setLayerAddress(_ v: UInt32) {
        data[0] = UInt8((v >> 24) & 0xFF)
        data[1] = UInt8((v >> 16) & 0xFF)
        data[2] = UInt8((v >> 8) & 0xFF)
        data[3] = UInt8(v & 0xFF)
    }

    // Tree address [4..15]
    public mutating func setTreeAddress(_ v: UInt64) {
        for i in 0..<8 {
            data[4 + (7 - i)] = UInt8((v >> (8 * i)) & 0xFF)
        }
        // Zero the first 4 bytes of tree address for padding
        data[4] = 0; data[5] = 0; data[6] = 0; data[7] = 0
        for i in 0..<8 {
            data[8 + (7 - i)] = UInt8((v >> (8 * i)) & 0xFF)
        }
    }

    public mutating func setTreeAddressBytes(_ v: UInt64) {
        // 12 bytes for tree: data[4..15]
        for i in 0..<4 { data[4 + i] = 0 }
        for i in 0..<8 {
            data[8 + (7 - i)] = UInt8((v >> (8 * i)) & 0xFF)
        }
    }

    // Type [16..19]
    public mutating func setType(_ v: UInt32) {
        data[16] = UInt8((v >> 24) & 0xFF)
        data[17] = UInt8((v >> 16) & 0xFF)
        data[18] = UInt8((v >> 8) & 0xFF)
        data[19] = UInt8(v & 0xFF)
        // Zero padding after type
        for i in 20..<32 { data[i] = 0 }
    }

    // Keypair address [20..23]
    public mutating func setKeyPairAddress(_ v: UInt32) {
        data[20] = UInt8((v >> 24) & 0xFF)
        data[21] = UInt8((v >> 16) & 0xFF)
        data[22] = UInt8((v >> 8) & 0xFF)
        data[23] = UInt8(v & 0xFF)
    }

    // Chain address [24..27]
    public mutating func setChainAddress(_ v: UInt32) {
        data[24] = UInt8((v >> 24) & 0xFF)
        data[25] = UInt8((v >> 16) & 0xFF)
        data[26] = UInt8((v >> 8) & 0xFF)
        data[27] = UInt8(v & 0xFF)
    }

    // Hash address [28..31]
    public mutating func setHashAddress(_ v: UInt32) {
        data[28] = UInt8((v >> 24) & 0xFF)
        data[29] = UInt8((v >> 16) & 0xFF)
        data[30] = UInt8((v >> 8) & 0xFF)
        data[31] = UInt8(v & 0xFF)
    }

    // Tree height [24..27]
    public mutating func setTreeHeight(_ v: UInt32) {
        setChainAddress(v)
    }

    // Tree index [28..31]
    public mutating func setTreeIndex(_ v: UInt32) {
        setHashAddress(v)
    }

    public func copy() -> SlhAddress {
        var a = SlhAddress()
        a.data = self.data
        return a
    }
}
