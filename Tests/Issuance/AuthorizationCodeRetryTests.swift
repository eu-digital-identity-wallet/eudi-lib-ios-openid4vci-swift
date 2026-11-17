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

/// RFC 6749 section 4.1.2: the client must not use the authorization code more than once.
final class AuthorizationCodeRetryTests: XCTestCase {

  func testErrorAfterTheRequestWasSent_doesNotSendTheCodeAgain() async throws {
    for code in [URLError.Code.timedOut, .networkConnectionLost, .badServerResponse] {
      let networking = FailingNetworking(error: URLError(code))
      do {
        _ = try await makeAuthorizer(networking).requestAccessTokenAuthFlow(
          authorizationCode: .init(value: "code"), codeVerifier: "verifier",
          identifiers: [], dpopNonce: nil, challenge: nil
        )
        XCTFail("Expected a network error for \(code)")
      } catch PostError.networkError {
        let count = await networking.requestCount
        XCTAssertEqual(count, 1, "The code was sent \(count) times for \(code)")
      }
    }
  }

  func testErrorBeforeTheRequestWasSent_retries() async throws {
    for code in [URLError.Code.notConnectedToInternet, .cannotFindHost, .dnsLookupFailed, .cannotConnectToHost] {
      let networking = FailingNetworking(error: URLError(code))
      do {
        _ = try await makeAuthorizer(networking).requestAccessTokenAuthFlow(
          authorizationCode: .init(value: "code"), codeVerifier: "verifier",
          identifiers: [], dpopNonce: nil, challenge: nil, maxRetries: 2
        )
        XCTFail("Expected a network error for \(code)")
      } catch PostError.networkError {
        let count = await networking.requestCount
        XCTAssertEqual(count, 3, "Expected the first request and 2 retries for \(code)")
      }
    }
  }

  // MARK: - Helpers

  private func makeAuthorizer(_ networking: FailingNetworking) throws -> AuthorizationServerClient {
    try AuthorizationServerClient(
      challenger: nil,
      parPoster: Poster(session: networking),
      tokenPoster: Poster(session: networking),
      config: OpenId4VCIConfig(
        client: .public(id: "test-client"),
        authFlowRedirectionURI: URL(string: "wallet://callback")!
      ),
      authorizationServerMetadata: .oauth(.init(
        issuer: "https://as.example.com",
        authorizationEndpoint: "https://as.example.com/authorize",
        tokenEndpoint: "https://as.example.com/token",
        pushedAuthorizationRequestEndpoint: "https://as.example.com/par"
      )),
      credentialIssuerIdentifier: .init("https://issuer.example.com"),
      dpopConstructor: nil
    )
  }
}

/// Fails every request with the same error and counts the requests.
private actor FailingNetworking: Networking {
  let error: URLError
  private(set) var requestCount = 0

  init(error: URLError) {
    self.error = error
  }

  func data(from url: URL) async throws -> (Data, URLResponse) {
    try await data(for: URLRequest(url: url))
  }

  func data(for request: URLRequest) async throws -> (Data, URLResponse) {
    requestCount += 1
    throw error
  }
}
