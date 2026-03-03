// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Privy",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        // Original Privy SDK (binary)
        .library(
            name: "Privy",
            targets: ["PrivySDK"]),
        // Aptos extension for Privy embedded wallets
        .library(
            name: "PrivyAptos",
            targets: ["PrivyAptos"]),
    ],
    dependencies: [],
    targets: [
        .binaryTarget(
            name: "PrivySDK",
            path: "PrivySDK.xcframework"),
        .target(
            name: "PrivyAptos",
            dependencies: ["PrivySDK"],
            path: "Sources/PrivyAptos"),
    ]
)
