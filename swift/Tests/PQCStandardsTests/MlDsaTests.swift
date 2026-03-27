import XCTest
@testable import PQCStandards

final class MlDsaTests: XCTestCase {
    func testMlDsa44Roundtrip() throws {
        let params = MlDsaParams.mlDsa44
        let kp = MlDsa.keyGen(params: params)
        let message: [UInt8] = Array("Hello ML-DSA-44!".utf8)
        let sig = MlDsa.sign(params: params, sk: kp.secretKey, message: message)
        XCTAssertNotNil(sig, "ML-DSA-44 signing should succeed")
        let valid = MlDsa.verify(params: params, pk: kp.publicKey, message: message, signature: sig!)
        XCTAssertTrue(valid, "ML-DSA-44 signature should verify")
    }

    func testMlDsa65Roundtrip() throws {
        let params = MlDsaParams.mlDsa65
        let kp = MlDsa.keyGen(params: params)
        let message: [UInt8] = Array("Hello ML-DSA-65!".utf8)
        let sig = MlDsa.sign(params: params, sk: kp.secretKey, message: message)
        XCTAssertNotNil(sig, "ML-DSA-65 signing should succeed")
        let valid = MlDsa.verify(params: params, pk: kp.publicKey, message: message, signature: sig!)
        XCTAssertTrue(valid, "ML-DSA-65 signature should verify")
    }

    func testMlDsa87Roundtrip() throws {
        let params = MlDsaParams.mlDsa87
        let kp = MlDsa.keyGen(params: params)
        let message: [UInt8] = Array("Hello ML-DSA-87!".utf8)
        let sig = MlDsa.sign(params: params, sk: kp.secretKey, message: message)
        XCTAssertNotNil(sig, "ML-DSA-87 signing should succeed")
        let valid = MlDsa.verify(params: params, pk: kp.publicKey, message: message, signature: sig!)
        XCTAssertTrue(valid, "ML-DSA-87 signature should verify")
    }

    func testMlDsaRejectTampered() throws {
        let params = MlDsaParams.mlDsa44
        let kp = MlDsa.keyGen(params: params)
        let message: [UInt8] = Array("Original message".utf8)
        let sig = MlDsa.sign(params: params, sk: kp.secretKey, message: message)
        XCTAssertNotNil(sig)

        let tampered: [UInt8] = Array("Tampered message".utf8)
        let valid = MlDsa.verify(params: params, pk: kp.publicKey, message: tampered, signature: sig!)
        XCTAssertFalse(valid, "Tampered message should not verify")
    }
}
