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
import Testing

@testable import OpenID4VCI

let ISSUER = "https://example.com"
let TOKEN_ENDPOINT = "https://example.com/token"
let PAR_ENDPOINT = "https://example.com/par"
let AUTHORIZATION_ENDPOINT = "https://example.com/authorize"
let REDIRECTION_URI = URL(string: "urn:ietf:wg:oauth:2.0:oob")!

@Suite(.serialized)
class AuthorizationServerClientTest {
  var sut: AuthorizationServerClient!
  
  let scopes: [Scope]!
  let identifiers: [CredentialConfigurationIdentifier]!
  let state = "state"
  let issuerState = "issuerState"
  let customParamKey = "customParamKey"
  let customParamValue = "customParamValue"
  let resource = "resource"
  
  init() {
    do {
      scopes = [try Scope("email"), try Scope("profile")]
      identifiers = [try CredentialConfigurationIdentifier(value: "org.iso.18013.5.1.mDL")]
    } catch {
      fatalError()
    }
  }
  
  @Test
  func testAuthorizationRequestUrlSuccess() async throws {

    sut = try .create()
    
    let (verifier, authorizationCodeURL) = try await sut.authorizationRequestUrl(
      scopes: scopes,
      credentialConfigurationIdentifiers: identifiers,
      state: state,
      issuerState: issuerState,
      additionalAuthorizationParameters: [customParamKey: customParamValue]
    )

    let params = authorizationCodeURL.url.queryParameters

    #expect(verifier.codeVerifier.isEmpty == false)
    #expect(verifier.codeVerifierMethod == "S256")
    #expect(params["code_challenge"] == PKCEGenerator.generateCodeChallenge(codeVerifier: verifier.codeVerifier))
    #expect(params["code_challenge_method"] == "S256")

    #expect(params["response_type"] == "code")
    #expect(params["client_id"] == attestionClient.id)
    #expect(params["redirect_uri"] == REDIRECTION_URI.absoluteString)
    #expect(params["scope"] == "email profile openid")
    #expect(params["state"] == state)
    #expect(params["issuer_state"] == issuerState)
    #expect(params[customParamKey] == customParamValue)
    #expect(params["credential_configuration_ids"] == nil)

    #expect(authorizationCodeURL.url.host == "example.com")
    #expect(authorizationCodeURL.url.path == "/authorize")
  }

  @Test
  func testAuthorizationRequestUrlThrowsWhenScopesAndIdentifiersEmpty() async throws {
    sut = try .create()
    await #expect(throws: ValidationError.self) {
      _ = try await sut.authorizationRequestUrl(
        scopes: [],
        credentialConfigurationIdentifiers: [],
        state: "test-state",
        issuerState: nil,
        additionalAuthorizationParameters: [:]
      )
    }
  }

  @Test
  func testAuthorizationRequestUrlThrowsWhenAuthorizationEndpointMissing() async throws {
    sut = try .create(authorizationEndpoint: nil)
    await #expect(throws: ValidationError.self) {
      _ = try await sut.authorizationRequestUrl(
        scopes: [try Scope("email")],
        credentialConfigurationIdentifiers: [],
        state: "test-state",
        issuerState: nil,
        additionalAuthorizationParameters: [:]
      )
    }
  }

  @Test
  func testSubmitPushedAuthorizationRequestComputesParametersCorrectly() async throws {

    let serviceMock = AuthorisationServiceMock()
    sut = try .create(service: serviceMock)
    
    let (verifier, _, _) = try await sut.submitPushedAuthorizationRequest(
      parUsage: .required(authorizationCodeDPoPBinding: true),
      scopes: scopes,
      credentialConfigurationIdentifiers: identifiers,
      state: state,
      issuerState: issuerState,
      resource: resource,
      additionalAuthorizationParameters: [customParamKey: customParamValue]
    )

    let params = serviceMock.capturedParameters

    #expect(params?["response_type"] == "code")
    #expect(params?["client_id"] == attestionClient.id)
    #expect(params?["redirect_uri"] == REDIRECTION_URI.absoluteString)
    #expect(params?["scope"] == "email profile")
    #expect(params?["state"] == state)
    #expect(params?["issuer_state"] == issuerState)
    #expect(params?["resource"] == resource)
    #expect(params?["code_challenge"] == PKCEGenerator.generateCodeChallenge(codeVerifier: verifier.codeVerifier))
    #expect(params?["code_challenge_method"] == "S256")
    #expect(params?[customParamKey] == customParamValue)
    #expect(params?["credential_configuration_ids"] == nil)
  }
}

extension OIDCProviderMetadata {
  static func create(
    authorizationEndpoint: String?,
    parEndpoint: String? = nil,
    issuer: String,
    tokenEndpoint: String
  ) -> OIDCProviderMetadata {
    var payload: [String: String] = [
      "issuer": issuer,
      "token_endpoint": tokenEndpoint
    ]

    if let authorizationEndpoint {
      payload["authorization_endpoint"] = authorizationEndpoint
    }

    if let parEndpoint {
      payload["pushed_authorization_request_endpoint"] = parEndpoint
    }

    return try! JSONDecoder().decode(
      OIDCProviderMetadata.self,
      from: try! JSONEncoder().encode(payload)
    )
  }
}

extension AuthorizationServerClient {
  static func create(
    service: AuthorisationServiceType = AuthorisationServiceMock(),
    parEndpoint: String? = PAR_ENDPOINT,
    tokenEndpoint: String = TOKEN_ENDPOINT,
    authorizationEndpoint: String? = AUTHORIZATION_ENDPOINT,
    issuer: String = ISSUER,
    redirectionURI: URL = REDIRECTION_URI
  ) throws -> AuthorizationServerClient {
    try AuthorizationServerClient(
      service: service,
      challenger: nil,
      config: OpenId4VCIConfig(
        client: attestionClient,
        authFlowRedirectionURI: redirectionURI,
        authorizeIssuanceConfig: .favorScopes
      ),
      authorizationServerMetadata: .oidc(
        .create(
          authorizationEndpoint: authorizationEndpoint,
          parEndpoint: parEndpoint,
          issuer: issuer,
          tokenEndpoint: tokenEndpoint
        )
      ),
      credentialIssuerIdentifier: try CredentialIssuerId(issuer)
    )
  }
}

private final class AuthorisationServiceMock: AuthorisationServiceType, @unchecked Sendable {
  var capturedParameters: [String: String]?

  func formPost<T: Codable & Sendable, U: Codable & Sendable>(
    poster: PostingType,
    url: URL,
    request: T
  ) async throws -> ResponseWithHeaders<U> {
    fatalError("Not implemented")
  }

  func formPost<T: Codable & Sendable, U: Codable & Sendable>(
    poster: PostingType,
    url: URL,
    request: T,
    headers: [String: String]
  ) async throws -> ResponseWithHeaders<U> {
    fatalError("Not implemented")
  }

  func formPost<U: Codable & Sendable>(
    poster: PostingType,
    url: URL,
    headers: [String: String],
    parameters: [String: String]
  ) async throws -> ResponseWithHeaders<U> {
    capturedParameters = parameters

    let json = #"{"request_uri": "https://example.com/par/123", "expires_in": 60}"#
    let body = try JSONDecoder().decode(U.self, from: json.data(using: .utf8)!)
    return ResponseWithHeaders(headers: [:], body: body)
  }

  func formPost<U: Codable & Sendable>(
    poster: PostingType,
    url: URL,
    headers: [String: String],
    body: [String: any Sendable],
    encryptionSpec: EncryptionSpec?
  ) async throws -> ResponseWithHeaders<U> {
    fatalError("Not implemented")
  }
}
