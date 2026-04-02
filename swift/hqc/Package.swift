// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "Hqc",
    platforms: [.macOS(.v13)],
    products: [.library(name: "Hqc", targets: ["Hqc"])],
    targets: [
        .target(name: "Hqc"),
        .testTarget(name: "HqcTests", dependencies: ["Hqc"]),
    ]
)
