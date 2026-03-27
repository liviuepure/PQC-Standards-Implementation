import XCTest
@testable import PQCStandards

final class SlhDsaTests: XCTestCase {
    func testSlhDsaShake128fRoundtrip() throws {
        let params = SlhDsaParams.shake128f
        let kp = SlhDsa.keyGen(params: params)
        let message: [UInt8] = Array("Hello SLH-DSA!".utf8)
        let sig = SlhDsa.sign(params: params, sk: kp.secretKey, message: message)
        let valid = SlhDsa.verify(params: params, pk: kp.publicKey, message: message, signature: sig)
        XCTAssertTrue(valid, "SLH-DSA-SHAKE-128f signature should verify")
    }
}
