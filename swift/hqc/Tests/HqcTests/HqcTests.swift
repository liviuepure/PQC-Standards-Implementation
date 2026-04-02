import XCTest
@testable import Hqc

final class HqcTests: XCTestCase {

    override class func setUp() {
        super.setUp()
        initGF256Tables()
    }

    // MARK: - GF(256) Tests

    func testGF256Tables() {
        for i in 1..<256 {
            let a = UInt8(i)
            let logA = gf256Pow(gfGenConst, Int(a))
            // Check exp(log(a)) == a via round-trip through mul/inv
            let inv = gf256Inv(a)
            let product = gf256Mul(a, inv)
            XCTAssertEqual(product, 1, "a * inv(a) should be 1 for a=\(a)")
        }
    }

    func testGF256Mul() {
        for i in 0..<256 {
            let a = UInt8(i)
            XCTAssertEqual(gf256Mul(1, a), a, "1 * \(a) should be \(a)")
        }
        for i in 1..<256 {
            let a = UInt8(i)
            XCTAssertEqual(gf256Mul(a, gf256Inv(a)), 1, "\(a) * inv(\(a)) should be 1")
        }
    }

    func testGF256MulCT() {
        // Test a subset to keep it fast
        for i in stride(from: 0, to: 256, by: 7) {
            for j in stride(from: 0, to: 256, by: 7) {
                let a = UInt8(i)
                let b = UInt8(j)
                XCTAssertEqual(gf256MulCT(a, b), gf256Mul(a, b),
                               "gf256MulCT(\(a),\(b)) mismatch")
            }
        }
    }

    // MARK: - GF(2) Vector Tests

    func testGF2VectOps() {
        let a: [UInt64] = [0xAAAA, 0x5555]
        let b: [UInt64] = [0x5555, 0xAAAA]
        let c = vectAdd(a, b)
        XCTAssertEqual(c[0], 0xFFFF)
        XCTAssertEqual(c[1], 0xFFFF)

        // Mul by identity
        let one: [UInt64] = [1, 0]
        let d: [UInt64] = [0xDEADBEEFCAFEBABE, 0x1234567890ABCDEF]
        let r = vectMul(d, one, 128)
        XCTAssertEqual(r[0], d[0])
        XCTAssertEqual(r[1], d[1])
    }

    func testVectMulProperties() {
        let n = 17669
        let se = SeedExpander([99])
        let h = vectSetRandomFixedWeight(se, n, 10)
        let y = vectSetRandomFixedWeight(se, n, 10)
        let r2 = vectSetRandomFixedWeight(se, n, 10)

        // Commutativity
        let hy = vectMul(h, y, n)
        let yh = vectMul(y, h, n)
        XCTAssertEqual(vectEqual(hy, yh), 1, "Multiplication should be commutative")

        // Associativity
        let hy_r2 = vectMul(hy, r2, n)
        let yr2 = vectMul(y, r2, n)
        let h_yr2 = vectMul(h, yr2, n)
        XCTAssertEqual(vectEqual(hy_r2, h_yr2), 1, "Multiplication should be associative")
    }

    // MARK: - Reed-Muller Tests

    func testRMEncodeDecodeRoundtrip() {
        for msg in 0..<256 {
            let m = UInt8(msg)
            for mult in [3, 5] {
                let n2 = mult * 128
                let nWords = (n2 + 63) / 64
                var cw = [UInt64](repeating: 0, count: nWords)
                rmEncodeInto(&cw, m, 0, mult)
                let decoded = rmDecode(cw, n2, mult)
                XCTAssertEqual(decoded, m,
                               "RM mult=\(mult) msg=\(msg): got \(decoded)")
            }
        }
    }

    // MARK: - Reed-Solomon Tests

    func testRSEncodeDecodeRoundtrip() {
        for p in allParams {
            var msg = [UInt8](repeating: 0, count: p.k)
            for i in 0..<msg.count { msg[i] = UInt8((i + 1) & 0xFF) }
            let cw = rsEncode(msg, p)
            let (decoded, ok) = rsDecode(cw, p)
            XCTAssertTrue(ok, "\(p.name): decode failed on clean codeword")
            XCTAssertEqual(decoded, msg, "\(p.name): roundtrip mismatch")
        }
    }

    func testRSDecodeWithErrors() {
        for p in allParams {
            var msg = [UInt8](repeating: 0, count: p.k)
            for i in 0..<msg.count { msg[i] = UInt8((i * 3 + 7) & 0xFF) }
            var cw = rsEncode(msg, p)
            // Introduce delta correctable errors
            for i in 0..<p.delta {
                cw[i] ^= UInt8((i + 1) & 0xFF)
            }
            let (decoded, ok) = rsDecode(cw, p)
            XCTAssertTrue(ok, "\(p.name): decode failed with correctable errors")
            XCTAssertEqual(decoded, msg, "\(p.name): decode mismatch after correction")
        }
    }

    // MARK: - Tensor Code Tests

    func testTensorEncodeDecodeRoundtrip() {
        for p in allParams {
            var msg = [UInt8](repeating: 0, count: p.k)
            for i in 0..<msg.count { msg[i] = UInt8((i + 42) & 0xFF) }
            let encoded = tensorEncode(msg, p)
            let (decoded, ok) = tensorDecode(encoded, p)
            XCTAssertTrue(ok, "\(p.name): tensor decode failed")
            XCTAssertEqual(decoded, msg, "\(p.name): tensor roundtrip mismatch")
        }
    }

    // MARK: - Vector Weight Tests

    func testVectorWeights() {
        for p in allParams {
            let se = SeedExpander([1, 2, 3])
            for _ in 0..<20 {
                let v = vectSetRandomFixedWeight(se, p.n, p.w)
                let w = vectWeight(v)
                XCTAssertEqual(w, p.w, "\(p.name): weight \(w), expected \(p.w)")
            }
        }
    }

    // MARK: - KEM Tests

    func testKEMRoundtrip() {
        for p in allParams {
            let (pk, sk) = hqcKeyGen(p)
            XCTAssertEqual(pk.count, p.pkSize, "\(p.name): pk size mismatch")
            XCTAssertEqual(sk.count, p.skSize, "\(p.name): sk size mismatch")

            let (ct, ss1) = hqcEncaps(pk, p)
            XCTAssertEqual(ct.count, p.ctSize, "\(p.name): ct size mismatch")
            XCTAssertEqual(ss1.count, p.ssSize, "\(p.name): ss size mismatch")

            let ss2 = hqcDecaps(sk, ct, p)
            XCTAssertEqual(ss1, ss2, "\(p.name): shared secrets don't match")
        }
    }

    func testKEMDecapsBadCiphertext() {
        let p = hqc128
        let (pk, sk) = hqcKeyGen(p)
        var (ct, ss1) = hqcEncaps(pk, p)
        ct[0] ^= 0xFF
        ct[1] ^= 0xFF
        let ss2 = hqcDecaps(sk, ct, p)
        XCTAssertNotEqual(ss1, ss2,
                          "Shared secrets should not match with corrupted ciphertext")
    }

    func testKEMMultipleRoundtrips() {
        for p in allParams {
            let trials = 5
            for i in 0..<trials {
                let (pk, sk) = hqcKeyGen(p)
                let (ct, ss1) = hqcEncaps(pk, p)
                let ss2 = hqcDecaps(sk, ct, p)
                XCTAssertEqual(ss1, ss2,
                               "\(p.name) trial \(i): shared secrets do not match")
            }
        }
    }
}
