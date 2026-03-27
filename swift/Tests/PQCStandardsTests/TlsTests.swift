import XCTest
@testable import PQCStandards

final class TlsTests: XCTestCase {
    func testNamedGroupDefinitions() {
        XCTAssertEqual(TlsNamedGroups.x25519.value, 0x001D)
        XCTAssertEqual(TlsNamedGroups.mlKem768.value, 0x0201)
        XCTAssertEqual(TlsNamedGroups.x25519MlKem768.value, 0x4588)
        XCTAssertEqual(TlsNamedGroups.allGroups.count, 7)
    }

    func testNamedGroupLookup() {
        let group = TlsNamedGroups.byValue(0x4588)
        XCTAssertNotNil(group)
        XCTAssertEqual(group?.name, "X25519MLKEM768")
    }

    func testSigAlgorithmDefinitions() {
        XCTAssertEqual(TlsSigAlgorithms.mlDsa65.value, 0x0902)
        XCTAssertEqual(TlsSigAlgorithms.allAlgorithms.count, 7)
    }

    func testCipherSuiteDefinitions() {
        XCTAssertEqual(TlsCipherSuites.aes128GcmSha256.value, 0x1301)
        XCTAssertEqual(TlsCipherSuites.allSuites.count, 3)
    }
}
