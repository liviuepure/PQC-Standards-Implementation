import XCTest
@testable import PQCStandards

final class MlKemTests: XCTestCase {
    func testMlKem512Roundtrip() throws {
        let params = MlKemParams.mlKem512
        let kp = MlKem.keyGen(params: params)
        let result = MlKem.encapsulate(params: params, ek: kp.encapsulationKey)
        let ss = MlKem.decapsulate(params: params, dk: kp.decapsulationKey, ct: result.ciphertext)
        XCTAssertEqual(result.sharedSecret, ss, "ML-KEM-512 roundtrip failed")
    }

    func testMlKem768Roundtrip() throws {
        let params = MlKemParams.mlKem768
        let kp = MlKem.keyGen(params: params)
        let result = MlKem.encapsulate(params: params, ek: kp.encapsulationKey)
        let ss = MlKem.decapsulate(params: params, dk: kp.decapsulationKey, ct: result.ciphertext)
        XCTAssertEqual(result.sharedSecret, ss, "ML-KEM-768 roundtrip failed")
    }

    func testMlKem1024Roundtrip() throws {
        let params = MlKemParams.mlKem1024
        let kp = MlKem.keyGen(params: params)
        let result = MlKem.encapsulate(params: params, ek: kp.encapsulationKey)
        let ss = MlKem.decapsulate(params: params, dk: kp.decapsulationKey, ct: result.ciphertext)
        XCTAssertEqual(result.sharedSecret, ss, "ML-KEM-1024 roundtrip failed")
    }

    func testMlKemImplicitRejection() throws {
        let params = MlKemParams.mlKem768
        let kp = MlKem.keyGen(params: params)
        let result = MlKem.encapsulate(params: params, ek: kp.encapsulationKey)

        // Tamper with ciphertext
        var tampered = result.ciphertext
        tampered[0] ^= 0xFF

        let ss = MlKem.decapsulate(params: params, dk: kp.decapsulationKey, ct: tampered)
        XCTAssertNotEqual(result.sharedSecret, ss, "Implicit rejection should produce different secret")
        XCTAssertEqual(ss.count, 32, "Rejection should still produce 32-byte secret")
    }
}
