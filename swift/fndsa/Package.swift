// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "FnDsa",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "FnDsa", targets: ["FnDsa"]),
    ],
    dependencies: [
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.3.0"),
    ],
    targets: [
        .target(name: "FnDsa", dependencies: [
            .product(name: "BigInt", package: "BigInt"),
        ]),
        .testTarget(name: "FnDsaTests", dependencies: ["FnDsa"]),
    ]
)
