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

/// When the wallet requires DPoP, the authorization server must not be able to silently
/// downgrade the access token to Bearer (CWE-757). Mirrors Android's
/// "Do not allow an AS to downgrade DPoP to Bearer access_token" (eudi-lib-jvm-openid4vci-kt #593).
final class DPoPDowngradeTests: XCTestCase {

  private enum Flow: CaseIterable {
    case authorizationCode, preAuthorizationCode, refreshWithClient, refreshWithClientId
  }

  private let client: Client = .public(id: "test-client")

  /// `nil` means the `token_type` field is omitted from the response.
  private let nonDpopTokenTypes: [String?] = ["Bearer", "bearer", nil, "N_A"]

  func testRequireDpop_nonDpopTokenTypeIsRejected_forEveryTokenExchange() async throws {
    for flow in Flow.allCases {
      for tokenType in nonDpopTokenTypes {
        let sut = try makeAuthorizer(requireDpop: true, tokenResponse: tokenResponse(tokenType))
        do {
          try await requestToken(flow: flow, sut: sut)
          XCTFail("Expected dpopRequiredButNotIssued for \(flow) with token_type \(tokenType ?? "<missing>")")
        } catch ValidationError.dpopRequiredButNotIssued(let issued) {
          XCTAssertEqual(issued, tokenType)
        }
      }
    }
  }

  func testRequireDpop_dpopTokenTypeIsAccepted_forEveryTokenExchange() async throws {
    for flow in Flow.allCases {
      for tokenType in ["DPoP", "dpop"] {
        let sut = try makeAuthorizer(requireDpop: true, tokenResponse: tokenResponse(tokenType))
        try await requestToken(flow: flow, sut: sut)
      }
    }
  }

  func testDpopNotRequired_bearerTokenTypeIsAccepted_forEveryTokenExchange() async throws {
    for flow in Flow.allCases {
      for tokenType in nonDpopTokenTypes {
        let sut = try makeAuthorizer(requireDpop: false, tokenResponse: tokenResponse(tokenType))
        try await requestToken(flow: flow, sut: sut)
      }
    }
  }

  func testDpopRequiredButNotIssued_errorDescription() {
    XCTAssertEqual(
      ValidationError.dpopRequiredButNotIssued(tokenType: "Bearer").errorDescription,
      "dpopRequiredButNotIssued: DPoP is required but the Authorization Server issued a Bearer token_type"
    )
    XCTAssertEqual(
      ValidationError.dpopRequiredButNotIssued(tokenType: nil).errorDescription,
      "dpopRequiredButNotIssued: DPoP is required but the Authorization Server issued a missing token_type"
    )
  }

  // MARK: - Helpers

  private func tokenResponse(_ tokenType: String?) -> String {
    guard let tokenType else {
      return #"{"access_token":"token","refresh_token":"refresh","expires_in":300}"#
    }
    return #"{"access_token":"token","refresh_token":"refresh","expires_in":300,"token_type":"\#(tokenType)"}"#
  }

  private func requestToken(flow: Flow, sut: AuthorizationServerClient) async throws {
    switch flow {
    case .authorizationCode:
      _ = try await sut.requestAccessTokenAuthFlow(
        authorizationCode: .init(value: "code"), codeVerifier: "verifier",
        identifiers: [], dpopNonce: nil, challenge: nil
      )
    case .preAuthorizationCode:
      _ = try await sut.requestAccessTokenPreAuthFlow(
        preAuthorizedCode: "code", txCode: nil, client: client, transactionCode: nil,
        identifiers: [], dpopNonce: nil, challenge: nil
      )
    case .refreshWithClient:
      _ = try await sut.refreshAccessToken(
        client: client, refreshToken: .init(refreshToken: "refresh"), dpopNonce: nil
      )
    case .refreshWithClientId:
      _ = try await sut.refreshAccessToken(
        clientId: "test-client", refreshToken: .init(refreshToken: "refresh"), dpopNonce: nil
      )
    }
  }

  private func makeAuthorizer(requireDpop: Bool, tokenResponse: String) throws -> AuthorizationServerClient {
    let networking = TokenResponseNetworking(body: tokenResponse)
    let config = OpenId4VCIConfig(
      client: client,
      authFlowRedirectionURI: URL(string: "wallet://callback")!,
      requireDpop: requireDpop
    )
    return try AuthorizationServerClient(
      challenger: nil,
      parPoster: Poster(session: networking),
      tokenPoster: Poster(session: networking),
      config: config,
      authorizationServerMetadata: .oauth(.init(
        issuer: "https://as.example.com",
        authorizationEndpoint: "https://as.example.com/authorize",
        tokenEndpoint: "https://as.example.com/token",
        pushedAuthorizationRequestEndpoint: "https://as.example.com/par"
      )),
      credentialIssuerIdentifier: .init("https://issuer.example.com"),
      dpopConstructor: requireDpop ? dpopConstructor(algorithms: [.init(.ES256)]) : nil
    )
  }
}

/// Answers every request with the same 200 token response.
private struct TokenResponseNetworking: Networking {
  let body: String

  func data(from url: URL) async throws -> (Data, URLResponse) {
    try await data(for: URLRequest(url: url))
  }

  func data(for request: URLRequest) async throws -> (Data, URLResponse) {
    (Data(body.utf8), HTTPURLResponse(
      url: request.url!, statusCode: 200, httpVersion: nil,
      headerFields: ["Content-Type": "application/json"]
    )!)
  }
}
