/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import Foundation
import XCTest

@testable import OpenID4VCI

class AuthorizationServerDiscoveryTests: XCTestCase {

  private final class StubNetworking: Networking, @unchecked Sendable {
    private let lock = NSLock()
    private let body: String
    private let statusCode: Int
    private var urls: [URL] = []

    init(body: String, statusCode: Int = 200) {
      self.body = body
      self.statusCode = statusCode
    }

    var requestedURLs: [URL] { lock.withLock { urls } }

    func data(from url: URL) async throws -> (Data, URLResponse) {
      lock.withLock { urls.append(url) }
      let response = HTTPURLResponse(url: url, statusCode: statusCode, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
      return (Data(body.utf8), response)
    }

    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
      try await data(from: request.url!)
    }
  }

  private let authorizationServer = URL(string: "https://as.example.com/tenant")!

  private func metadata(issuer: String) -> String {
    """
    {"issuer": "\(issuer)", "token_endpoint": "https://as.example.com/tenant/token"}
    """
  }

  func testIssuerMismatchStopsDiscovery() async {
    let oauth = StubNetworking(body: metadata(issuer: "https://as.example.com/tenant/INVALID"))
    let oidc = StubNetworking(body: metadata(issuer: authorizationServer.absoluteString))
    let resolver = AuthorizationServerMetadataResolver(
      oidcFetcher: Fetcher(session: oidc),
      oauthFetcher: Fetcher(session: oauth)
    )

    let result = await resolver.resolve(url: authorizationServer)

    guard case .failure = result else {
      return XCTFail("Expected failure for an issuer mismatch")
    }
    XCTAssertTrue(oidc.requestedURLs.isEmpty)
  }

  func testMissingOAuthMetadataFallsBackToOpenIDConfiguration() async {
    let oauth = StubNetworking(body: "{}", statusCode: 404)
    let oidc = StubNetworking(body: metadata(issuer: authorizationServer.absoluteString))
    let resolver = AuthorizationServerMetadataResolver(
      oidcFetcher: Fetcher(session: oidc),
      oauthFetcher: Fetcher(session: oauth)
    )

    let result = await resolver.resolve(url: authorizationServer)

    guard case .success(.oidc) = result else {
      return XCTFail("Expected the OpenID configuration")
    }
    XCTAssertEqual(oidc.requestedURLs.map(\.path), ["/.well-known/openid-configuration/tenant"])
  }
}
