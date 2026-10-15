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
@preconcurrency import JOSESwift
import SwiftyJSON

@testable import OpenID4VCI

final class ClientAttestationChallengeTests: XCTestCase {
  private enum Flow: CaseIterable, Equatable {
    case par, authorizationCode, preAuthorizationCode, refresh
  }

  func testDpopRetry_rebuildsProofWithFreshChallenge_forEveryAttestedExchange() async throws {
    for flow in Flow.allCases {
      for useAuthenticateHeader in [false, true] {
        let client = try makeClient()
        var headers = [
          "dpop-nonce": "fresh-dpop-nonce",
          "oauth-client-attestation-challenge": "fresh-challenge"
        ]
        if useAuthenticateHeader {
          headers["WWW-Authenticate"] = "DPoP error=\"use_dpop_nonce\""
        }
        let success = flow == .par
          ? #"{"request_uri":"https://as.example.com/request/1","expires_in":60}"#
          : #"{"access_token":"token","token_type":"DPoP","expires_in":300}"#
        let networking = ChallengeSequenceNetworking(responses: [
          .init(status: useAuthenticateHeader ? 401 : 400, headers: headers, body: #"{"error":"use_dpop_nonce"}"#),
          .init(status: 200, headers: [:], body: success)
        ])
        let challenger = ChallengeEndpointClient(
          poster: Poster(session: NetworkingThrowingMock()),
          challengeEndpoint: URL(string: "https://as.example.com/challenge")!
        )
        await challenger.setChallenge(Nonce(value: "old-challenge"))
        let sut = try makeAuthorizer(client: client, networking: networking, challenger: challenger)

        switch flow {
        case .par:
          _ = try await sut.submitPushedAuthorizationRequest(
            parUsage: .required(authorizationCodeDPoPBinding: true),
            scopes: [try Scope("openid")],
            credentialConfigurationIdentifiers: [],
            state: "state", issuerState: nil,
            challenge: Nonce(value: "old-challenge")
          )
        case .authorizationCode:
          _ = try await sut.requestAccessTokenAuthFlow(
            authorizationCode: .init(value: "code"), codeVerifier: "verifier",
            identifiers: [], dpopNonce: nil, challenge: Nonce(value: "old-challenge")
          )
        case .preAuthorizationCode:
          _ = try await sut.requestAccessTokenPreAuthFlow(
            preAuthorizedCode: "code", txCode: nil, client: client, transactionCode: nil,
            identifiers: [], dpopNonce: nil, challenge: Nonce(value: "old-challenge")
          )
        case .refresh:
          _ = try await sut.refreshAccessToken(
            client: client, refreshToken: .init(refreshToken: "refresh"), dpopNonce: nil
          )
        }

        let requests = await networking.requests
        XCTAssertEqual(requests.count, 2)
        let firstProof = try proof(in: XCTUnwrap(requests.first))
        let retryProof = try proof(in: XCTUnwrap(requests.last))
        XCTAssertEqual(firstProof["challenge"].string, "old-challenge")
        XCTAssertEqual(retryProof["challenge"].string, "fresh-challenge")
        XCTAssertNotEqual(firstProof["jti"].string, retryProof["jti"].string)
        let retryDpop = try JWS(compactSerialization: XCTUnwrap(requests.last?.value(forHTTPHeaderField: "DPoP")))
        XCTAssertEqual(JSON(retryDpop.payload.data())["nonce"].string, "fresh-dpop-nonce")
      }
    }
  }

  func testAuthorizationCode_challengeFailurePreventsTokenRequest() async throws {
    let networking = ChallengeSequenceNetworking(responses: [])
    let challenger = ChallengeEndpointClient(
      poster: Poster(session: NetworkingThrowingMock()),
      challengeEndpoint: URL(string: "https://as.example.com/challenge")!
    )
    let authorizer = try makeAuthorizer(client: makeClient(), networking: networking, challenger: challenger)
    let sut = try AuthorizeIssuance(
      config: await authorizer.config, authorizer: authorizer, challenger: challenger,
      issuerMetadata: .init(deferredCredentialEndpoint: nil)
    )
    let request = AuthorizationRequested(
      credentials: [], authorizationCodeURL: try .init(urlString: "https://as.example.com/authorize?client_id=test-client"),
      pkceVerifier: try .init(codeVerifier: "verifier", codeVerifierMethod: "S256"),
      state: "state", configurationIds: [], expectedIssuer: nil, issParameterRequired: false
    )
    do {
      _ = try await sut.authorizeWithAuthorizationCode(
        grant: .authorizationCode(.init(authorizationServer: nil)), request: request,
        authorizationCode: .init(value: "code"), authorizationDetailsInTokenRequest: .doNotInclude
      )
      XCTFail("Expected the challenge failure to propagate")
    } catch PostError.networkError {
      // A failed challenge must stop issuance before a token request is sent.
    }
    let requests = await networking.requests
    XCTAssertTrue(requests.isEmpty)
  }

  func testRefresh_challengeFailurePreventsTokenRequest() async throws {
    let client = try makeClient()
    let networking = ChallengeSequenceNetworking(responses: [])
    let challenger = ChallengeEndpointClient(
      poster: Poster(session: NetworkingThrowingMock()),
      challengeEndpoint: URL(string: "https://as.example.com/challenge")!
    )
    let sut = try makeAuthorizer(client: client, networking: networking, challenger: challenger)
    do {
      _ = try await sut.refreshAccessToken(
        client: client, refreshToken: .init(refreshToken: "refresh"), dpopNonce: nil
      )
      XCTFail("Expected the challenge failure to propagate")
    } catch PostError.networkError {
      // The transport failure must escape before any token exchange.
    }
    let requests = await networking.requests
    XCTAssertTrue(requests.isEmpty)
  }

  func testRefresh_usesRetryChallengeWithoutChallengeEndpoint() async throws {
    let client = try makeClient()
    let networking = ChallengeSequenceNetworking(responses: [
      .init(status: 400, headers: [
        "DPoP-Nonce": "fresh-dpop-nonce",
        "OAuth-Client-Attestation-Challenge": "fresh-challenge"
      ], body: #"{"error":"use_dpop_nonce"}"#),
      .init(status: 200, headers: [:], body: #"{"access_token":"token","token_type":"DPoP"}"#)
    ])
    let sut = try makeAuthorizer(client: client, networking: networking, challenger: nil)
    _ = try await sut.refreshAccessToken(
      client: client, refreshToken: .init(refreshToken: "refresh"), dpopNonce: nil
    )
    let requests = await networking.requests
    XCTAssertEqual(try proof(in: XCTUnwrap(requests.last))["challenge"].string, "fresh-challenge")
  }

  func testIssuer_sessionTransportHandlesChallengeAndRefresh() async throws {
    let client = try makeClient()
    let networking = ChallengeSequenceNetworking(responses: [
      .init(status: 200, headers: ["DPoP-Nonce": "challenge-dpop-nonce"],
            body: #"{"attestation_challenge":"transport-challenge"}"#),
      .init(status: 200, headers: [:], body: #"{"access_token":"token","token_type":"DPoP"}"#)
    ])
    let config = OpenId4VCIConfig(
      client: client, authFlowRedirectionURI: URL(string: "wallet://callback")!,
      clientAttestationPoPBuilder: DefaultClientAttestationPoPBuilder(), requireDpop: false
    )
    let issuer = try Issuer(
      authorizationServerMetadata: .oauth(.init(
        issuer: "https://as.example.com", tokenEndpoint: "https://as.example.com/token",
        challengeEndpoint: "https://as.example.com/challenge"
      )),
      issuerMetadata: .init(deferredCredentialEndpoint: nil),
      config: config, session: networking
    )
    let authorized = AuthorizedRequest(
      accessToken: try .init(accessToken: "old-token", tokenType: .init(value: "Bearer")),
      refreshToken: try .init(refreshToken: "refresh"),
      credentialIdentifiers: nil, timeStamp: 0, dPopNonce: nil, grantType: nil
    )
    _ = try await issuer.refresh(authorizedRequest: authorized, dPopNonce: nil)
    let requests = await networking.requests
    XCTAssertEqual(requests.map { $0.url?.path }, ["/challenge", "/token"])
    XCTAssertEqual(try proof(in: XCTUnwrap(requests.last))["challenge"].string, "transport-challenge")
  }

  func testEmptyChallengeResponseFails() async throws {
    let networking = ChallengeSequenceNetworking(responses: [
      .init(status: 200, headers: [:], body: #"{"attestation_challenge":""}"#)
    ])
    let challenger = ChallengeEndpointClient(
      poster: Poster(session: networking), challengeEndpoint: URL(string: "https://as.example.com/challenge")!
    )
    do {
      _ = try await challenger.getChallenge()
      XCTFail("Expected empty challenge to fail")
    } catch ValidationError.error(let reason) {
      XCTAssertTrue(reason.contains("empty attestation challenge"))
    }
  }

  private func makeAuthorizer(
    client: Client,
    networking: any Networking,
    challenger: (any ChallengeEndpointClientType)?
  ) throws -> AuthorizationServerClient {
    let config = OpenId4VCIConfig(
      client: client, authFlowRedirectionURI: URL(string: "wallet://callback")!,
      clientAttestationPoPBuilder: DefaultClientAttestationPoPBuilder(), requireDpop: false
    )
    return try AuthorizationServerClient(
      challenger: challenger,
      parPoster: Poster(session: networking), tokenPoster: Poster(session: networking),
      config: config,
      authorizationServerMetadata: .oauth(.init(
        issuer: "https://as.example.com", authorizationEndpoint: "https://as.example.com/authorize",
        tokenEndpoint: "https://as.example.com/token",
        pushedAuthorizationRequestEndpoint: "https://as.example.com/par"
      )),
      credentialIssuerIdentifier: .init("https://issuer.example.com"),
      dpopConstructor: dpopConstructor(algorithms: [.init(.ES256)])
    )
  }

  private func makeClient() throws -> Client {
    let privateKey = try KeyController.generateECDHPrivateKey()
    let jwk = try ECPublicKey(publicKey: KeyController.generateECDHPublicKey(from: privateKey))
    let signingKey = SigningKeyProxy.secKey(privateKey)
    return try .attested(
      id: "test-client", alg: .init(.ES256), jwk: jwk,
      popJwtSpec: .init(signingAlgorithm: .ES256, duration: 300, typ: "oauth-client-attestation-pop+jwt"),
      clientAttestationProvider: { _ in (ClientAttestationJWT(""), signingKey) }
    )
  }

  private func proof(in request: URLRequest) throws -> JSON {
    let value = try XCTUnwrap(request.value(forHTTPHeaderField: "OAuth-Client-Attestation-PoP"))
    return JSON(try JWS(compactSerialization: value).payload.data())
  }
}

private actor ChallengeSequenceNetworking: Networking {
  struct Response: Sendable {
    let status: Int
    let headers: [String: String]
    let body: String
  }
  private var responses: [Response]
  private(set) var requests: [URLRequest] = []

  init(responses: [Response]) { self.responses = responses }

  func data(from url: URL) async throws -> (Data, URLResponse) {
    try await data(for: URLRequest(url: url))
  }

  func data(for request: URLRequest) async throws -> (Data, URLResponse) {
    requests.append(request)
    guard !responses.isEmpty else {
      throw ValidationError.error(reason: "Unexpected network request")
    }
    let response = responses.removeFirst()
    return (Data(response.body.utf8), HTTPURLResponse(
      url: request.url!, statusCode: response.status,
      httpVersion: nil, headerFields: response.headers
    )!)
  }
}
