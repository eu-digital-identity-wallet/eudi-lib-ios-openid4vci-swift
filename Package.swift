// swift-tools-version: 5.8
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
  name: "OpenID4VCI",
  platforms: [.iOS(.v14), .macOS(.v12)],
  products: [
    .library(
      name: "OpenID4VCI",
      targets: ["OpenID4VCI"]
    ),
  ],
  targets: [
    .target(
      name: "OpenID4VCI",
      dependencies: [
      ],
      path: "Sources"
    ),
    .testTarget(
      name: "OpenID4VCITests",
      dependencies: ["OpenID4VCI"],
      path: "Tests"
    ),
  ]
)
