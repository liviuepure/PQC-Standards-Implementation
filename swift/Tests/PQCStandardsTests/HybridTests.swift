import XCTest
@testable import PQCStandards

final class HybridTests: XCTestCase {
    func testX25519MlKem768Roundtrip() throws {
        let params = MlKemParams.mlKem768
        let kp = HybridKem.keyGen(params: params)
        let result = HybridKem.encapsulate(
            params: params,
            classicalPublicKey: kp.classicalPublicKey,
            pqPublicKey: kp.pqPublicKey
        )
        let ss = HybridKem.decapsulate(
            params: params,
            classicalSecretKey: kp.classicalSecretKey,
            pqSecretKey: kp.pqSecretKey,
            classicalCiphertext: result.classicalCiphertext,
            pqCiphertext: result.pqCiphertext
        )
        XCTAssertEqual(result.sharedSecret, ss, "Hybrid X25519+ML-KEM-768 roundtrip failed")
        XCTAssertEqual(ss.count, 32, "Shared secret should be 32 bytes")
    }
}
