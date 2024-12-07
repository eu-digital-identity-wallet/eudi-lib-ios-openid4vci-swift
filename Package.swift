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
  dependencies: [
    .package(url: "https://github.com/SwiftyJSON/SwiftyJSON.git", from: "5.0.1"),
    .package(url: "https://github.com/scinfu/SwiftSoup.git", from: "2.6.0"),
    .package(
      url: "https://github.com/airsidemobile/JOSESwift.git",
      from: "3.0.0"
    ),
  ],
  targets: [
    .target(
      name: "OpenID4VCI",
      dependencies: [
        .product(
          name: "SwiftyJSON",
          package: "SwiftyJSON"
        ),
        .product(
          name: "JOSESwift",
          package: "JOSESwift"
        )
      ],
      path: "Sources",
      resources: [
        .process("Resources")
      ]
    ),
    .testTarget(
      name: "OpenID4VCITests",
      dependencies: [
        "OpenID4VCI",
        .product(
          name: "SwiftyJSON",
          package: "SwiftyJSON"
        ),
        .product(
          name: "SwiftSoup",
          package: "SwiftSoup"
        )
      ],
      path: "Tests"
    ),
  ]
)
