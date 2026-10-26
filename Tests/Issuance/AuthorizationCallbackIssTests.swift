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

/// RFC 9207 iss-parameter validation on the authorization callback path,
/// driven by `OpenId4VCIConfig.authResponseIssChecking`.
final class AuthorizationCallbackIssTests: XCTestCase {

  private let issuerURL = URL(string: "https://as.example.com")!

  private func makeConfig(_ policy: AuthorizationResponseIssChecking) -> OpenId4VCIConfig {
    .init(
      client: attestionClient,
      authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!,
      authorizeIssuanceConfig: .favorScopes,
      clientAttestationPoPBuilder: DefaultClientAttestationPoPBuilder(),
      authResponseIssChecking: policy
    )
  }

  private func makeIssuer(
    from offer: CredentialOffer,
    policy: AuthorizationResponseIssChecking
  ) throws -> Issuer {
    try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: makeConfig(policy),
      parPoster: Poster(session: NetworkingMock(path: "pushed_authorization_request_response", extension: "json")),
      tokenPoster: Poster(session: NetworkingMock(path: "access_token_request_response_no_proof", extension: "json")),
      dpopConstructor: dpopConstructor(algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported)
    )
  }

  private func makeAuthorizationRequested(
    expectedIssuer: URL?,
    issParameterRequired: Bool
  ) throws -> AuthorizationRequested {
    AuthorizationRequested(
      credentials: [try .init(value: "UniversityDegree_JWT")],
      authorizationCodeURL: try .init(
        urlString: "https://example.com?client_id=\(WALLET_DEV_CLIENT_ID)&request_uri=https://request_uri.example.com&state=state-1"
      ),
      pkceVerifier: try .init(
        codeVerifier: "GVaOE~J~xQmkE4aCKm4RNYviYW5QaFiFOxVv-8enIDL",
        codeVerifierMethod: "S256"
      ),
      state: "state-1",
      configurationIds: [try .init(value: "my_credential_configuration_id")],
      expectedIssuer: expectedIssuer,
      issParameterRequired: issParameterRequired
    )
  }

  /// The mock AS metadata advertises `authorization_response_iss_parameter_supported: true`;
  /// returns a copy of the offer whose AS does not.
  private func withoutIssParameterSupport(_ offer: CredentialOffer) throws -> CredentialOffer {
    let path = try XCTUnwrap(Bundle.module.path(forResource: "oidc_authorization_server_metadata", ofType: "json"))
    var json = try XCTUnwrap(
      JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: path))) as? [String: Any]
    )
    json["authorization_response_iss_parameter_supported"] = false
    let patched = try JSONDecoder().decode(
      OIDCProviderMetadata.self,
      from: JSONSerialization.data(withJSONObject: json)
    )
    return try CredentialOffer(
      credentialIssuerIdentifier: offer.credentialIssuerIdentifier,
      credentialIssuerMetadata: offer.credentialIssuerMetadata,
      credentialConfigurationIdentifiers: offer.credentialConfigurationIdentifiers,
      grants: offer.grants,
      authorizationServerMetadata: .oidc(patched)
    )
  }

  private func assertMissingIss(_ expression: @autoclosure () throws -> Void) {
    XCTAssertThrowsError(try expression()) { error in
      guard case ValidationError.issParameterRequiredButMissing(let expected) = error else {
        return XCTFail("Unexpected error: \(error)")
      }
      XCTAssertEqual(expected, issuerURL.absoluteString)
    }
  }

  private func assertMismatchedIss(_ expression: @autoclosure () throws -> Void, actual: URL) {
    XCTAssertThrowsError(try expression()) { error in
      guard case ValidationError.issMismatch(let expected, let received) = error else {
        return XCTFail("Unexpected error: \(error)")
      }
      XCTAssertEqual(expected, issuerURL.absoluteString)
      XCTAssertEqual(received, actual.absoluteString)
    }
  }

  // MARK: - IfSupported

  func testIfSupported_validIssSucceeds() throws {
    let request = try makeAuthorizationRequested(expectedIssuer: issuerURL, issParameterRequired: true)
    XCTAssertNoThrow(try Issuer.validateIssuer(issuerURL, for: request, policy: .ifSupported))
  }

  func testIfSupported_mismatchedIssFails() throws {
    let request = try makeAuthorizationRequested(expectedIssuer: issuerURL, issParameterRequired: true)
    let attacker = URL(string: "https://attacker.example.com")!
    assertMismatchedIss(try Issuer.validateIssuer(attacker, for: request, policy: .ifSupported), actual: attacker)
  }

  func testIfSupported_missingIssWhenSupportedFails() throws {
    let request = try makeAuthorizationRequested(expectedIssuer: issuerURL, issParameterRequired: true)
    assertMissingIss(try Issuer.validateIssuer(nil, for: request, policy: .ifSupported))
  }

  func testIfSupported_missingIssWhenNotSupportedSucceeds() throws {
    let request = try makeAuthorizationRequested(expectedIssuer: issuerURL, issParameterRequired: false)
    XCTAssertNoThrow(try Issuer.validateIssuer(nil, for: request, policy: .ifSupported))
  }

  /// Stricter than Android: RFC 9207 §2.4 requires checking `iss` whenever it is present,
  /// even if the AS did not advertise support.
  func testIfSupported_mismatchedIssWhenNotSupportedFails() throws {
    let request = try makeAuthorizationRequested(expectedIssuer: issuerURL, issParameterRequired: false)
    let attacker = URL(string: "https://attacker.example.com")!
    assertMismatchedIss(try Issuer.validateIssuer(attacker, for: request, policy: .ifSupported), actual: attacker)
  }

  func testIfSupported_issWithoutExpectedIssuerFails() throws {
    let request = try makeAuthorizationRequested(expectedIssuer: nil, issParameterRequired: false)
    XCTAssertThrowsError(try Issuer.validateIssuer(issuerURL, for: request, policy: .ifSupported))
  }

  // MARK: - Never

  func testNever_missingIssSucceeds() throws {
    let request = try makeAuthorizationRequested(expectedIssuer: issuerURL, issParameterRequired: true)
    XCTAssertNoThrow(try Issuer.validateIssuer(nil, for: request, policy: .never))
  }

  func testNever_mismatchedIssIsIgnored() throws {
    let request = try makeAuthorizationRequested(expectedIssuer: issuerURL, issParameterRequired: true)
    let attacker = URL(string: "https://attacker.example.com")!
    XCTAssertNoThrow(try Issuer.validateIssuer(attacker, for: request, policy: .never))
  }

  // MARK: - Required

  func testRequired_validIssSucceeds() throws {
    let request = try makeAuthorizationRequested(expectedIssuer: issuerURL, issParameterRequired: true)
    XCTAssertNoThrow(try Issuer.validateIssuer(issuerURL, for: request, policy: .required))
  }

  func testRequired_missingIssFails() throws {
    let request = try makeAuthorizationRequested(expectedIssuer: issuerURL, issParameterRequired: true)
    assertMissingIss(try Issuer.validateIssuer(nil, for: request, policy: .required))
  }

  func testRequired_asSupportsIssParamRequiresIssOnPrepare() async throws {
    guard let offer = await TestsConstants.createMockCredentialOffer() else {
      return XCTFail("Unable to create mock credential offer")
    }
    let issuer = try makeIssuer(from: offer, policy: .required)

    let request = try await issuer.prepareAuthorizationRequest(credentialOffer: offer)
    XCTAssertTrue(request.issParameterRequired)
    XCTAssertEqual(request.expectedIssuer?.absoluteString, offer.authorizationServerMetadata.issuer)
  }

  func testRequired_asDoesNotSupportIssParamFailsOnPrepare() async throws {
    guard let mockOffer = await TestsConstants.createMockCredentialOffer() else {
      return XCTFail("Unable to create mock credential offer")
    }
    let offer = try withoutIssParameterSupport(mockOffer)
    let issuer = try makeIssuer(from: offer, policy: .required)

    do {
      _ = try await issuer.prepareAuthorizationRequest(credentialOffer: offer)
      XCTFail("Expected issParameterNotSupported")
    } catch ValidationError.issParameterNotSupported {
      // expected
    }
  }

  // MARK: - Policy wiring

  func testPrepareAuthorizationRequest_ifSupportedWhenAsSupportsRequiresIss() async throws {
    guard let offer = await TestsConstants.createMockCredentialOffer() else {
      return XCTFail("Unable to create mock credential offer")
    }
    let issuer = try makeIssuer(from: offer, policy: .ifSupported)

    let request = try await issuer.prepareAuthorizationRequest(credentialOffer: offer)
    XCTAssertTrue(request.issParameterRequired)
  }

  func testPrepareAuthorizationRequest_ifSupportedWhenAsDoesNotSupportDoesNotRequireIss() async throws {
    guard let mockOffer = await TestsConstants.createMockCredentialOffer() else {
      return XCTFail("Unable to create mock credential offer")
    }
    let offer = try withoutIssParameterSupport(mockOffer)
    let issuer = try makeIssuer(from: offer, policy: .ifSupported)

    let request = try await issuer.prepareAuthorizationRequest(credentialOffer: offer)
    XCTAssertFalse(request.issParameterRequired)
  }

  func testPrepareAuthorizationRequest_neverDoesNotRequireIss() async throws {
    guard let offer = await TestsConstants.createMockCredentialOffer() else {
      return XCTFail("Unable to create mock credential offer")
    }
    let issuer = try makeIssuer(from: offer, policy: .never)

    let request = try await issuer.prepareAuthorizationRequest(credentialOffer: offer)
    XCTAssertFalse(request.issParameterRequired)
  }

  func testAuthorizeWithAuthorizationCode_enforcesRequiredIss() async throws {
    guard let offer = await TestsConstants.createMockCredentialOffer() else {
      return XCTFail("Unable to create mock credential offer")
    }
    let issuer = try makeIssuer(from: offer, policy: .ifSupported)
    let request = try makeAuthorizationRequested(expectedIssuer: issuerURL, issParameterRequired: true)

    do {
      _ = try await issuer.authorizeWithAuthorizationCode(
        serverState: request.state,
        request: request,
        authorizationCode: try AuthorizationCode(value: UUID().uuidString),
        grant: offer.grants!,
        issuerFromRedirect: nil
      )
      XCTFail("Expected issParameterRequiredButMissing")
    } catch ValidationError.issParameterRequiredButMissing {
      // expected
    }
  }
}
