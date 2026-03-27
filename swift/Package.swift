// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PQCStandards",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "PQCStandards", targets: ["PQCStandards"]),
    ],
    dependencies: [],
    targets: [
        .target(name: "PQCStandards"),
        .testTarget(name: "PQCStandardsTests", dependencies: ["PQCStandards"]),
    ]
)
