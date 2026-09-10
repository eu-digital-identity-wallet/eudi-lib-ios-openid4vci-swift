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

class SupportedGrantsTests: XCTestCase {

  // MARK: - SupportedGrants.supports() Tests

  func testAuthorizationCodeSupportsAuthorizationCodeGrant() throws {
    let supportedGrants = SupportedGrants.authorizationCode
    let grants = Grants.authorizationCode(
      try Grants.AuthorizationCode(issuerState: "test-state", authorizationServer: nil)
    )

    XCTAssertTrue(supportedGrants.supports(grants))
  }

  func testAuthorizationCodeDoesNotSupportPreAuthorizedCodeGrant() throws {
    let supportedGrants = SupportedGrants.authorizationCode
    let grants = Grants.preAuthorizedCode(
      Grants.PreAuthorizedCode(preAuthorizedCode: "pre-auth-code", txCode: nil, authorizationServer: nil)
    )

    XCTAssertFalse(supportedGrants.supports(grants))
  }

  func testPreAuthorizedCodeSupportsPreAuthorizedCodeGrant() throws {
    let supportedGrants = SupportedGrants.preAuthorizedCode
    let grants = Grants.preAuthorizedCode(
      Grants.PreAuthorizedCode(preAuthorizedCode: "pre-auth-code", txCode: nil, authorizationServer: nil)
    )

    XCTAssertTrue(supportedGrants.supports(grants))
  }

  func testPreAuthorizedCodeDoesNotSupportAuthorizationCodeGrant() throws {
    let supportedGrants = SupportedGrants.preAuthorizedCode
    let grants = Grants.authorizationCode(
      try Grants.AuthorizationCode(issuerState: "test-state", authorizationServer: nil)
    )

    XCTAssertFalse(supportedGrants.supports(grants))
  }

  func testBothSupportsAuthorizationCodeGrant() throws {
    let supportedGrants = SupportedGrants.both
    let grants = Grants.authorizationCode(
      try Grants.AuthorizationCode(issuerState: "test-state", authorizationServer: nil)
    )

    XCTAssertTrue(supportedGrants.supports(grants))
  }

  func testBothSupportsPreAuthorizedCodeGrant() throws {
    let supportedGrants = SupportedGrants.both
    let grants = Grants.preAuthorizedCode(
      Grants.PreAuthorizedCode(preAuthorizedCode: "pre-auth-code", txCode: nil, authorizationServer: nil)
    )

    XCTAssertTrue(supportedGrants.supports(grants))
  }

  func testBothSupportsBothGrants() throws {
    let supportedGrants = SupportedGrants.both
    let grants = Grants.both(
      try Grants.AuthorizationCode(issuerState: "test-state", authorizationServer: nil),
      Grants.PreAuthorizedCode(preAuthorizedCode: "pre-auth-code", txCode: nil, authorizationServer: nil)
    )

    XCTAssertTrue(supportedGrants.supports(grants))
  }

  func testAuthorizationCodeSupportsBothGrantsFromOffer() throws {
    let supportedGrants = SupportedGrants.authorizationCode
    let grants = Grants.both(
      try Grants.AuthorizationCode(issuerState: "test-state", authorizationServer: nil),
      Grants.PreAuthorizedCode(preAuthorizedCode: "pre-auth-code", txCode: nil, authorizationServer: nil)
    )

    // Authorization code wallet can use the authorization_code grant from a "both" offer
    XCTAssertTrue(supportedGrants.supports(grants))
  }

  func testPreAuthorizedCodeSupportsBothGrantsFromOffer() throws {
    let supportedGrants = SupportedGrants.preAuthorizedCode
    let grants = Grants.both(
      try Grants.AuthorizationCode(issuerState: "test-state", authorizationServer: nil),
      Grants.PreAuthorizedCode(preAuthorizedCode: "pre-auth-code", txCode: nil, authorizationServer: nil)
    )

    // Pre-authorized code wallet can use the pre-authorized_code grant from a "both" offer
    XCTAssertTrue(supportedGrants.supports(grants))
  }

  // MARK: - requiresAuthorizationCodeFlow Tests

  func testAuthorizationCodeRequiresAuthorizationCodeFlow() {
    XCTAssertTrue(SupportedGrants.authorizationCode.requiresAuthorizationCodeFlow)
  }

  func testPreAuthorizedCodeDoesNotRequireAuthorizationCodeFlow() {
    XCTAssertFalse(SupportedGrants.preAuthorizedCode.requiresAuthorizationCodeFlow)
  }

  func testBothRequiresAuthorizationCodeFlow() {
    XCTAssertTrue(SupportedGrants.both.requiresAuthorizationCodeFlow)
  }

  // MARK: - OpenId4VCIConfig Validation Tests

  func testConfigWithAuthorizationCodeGrantsRequiresRedirectionURI() throws {
    XCTAssertThrowsError(
      try OpenId4VCIConfig(
        client: .public(id: "test-client"),
        authFlowRedirectionURI: nil,
        supportedGrants: .authorizationCode
      )
    ) { error in
      guard case ValidationError.error(let reason) = error else {
        XCTFail("Expected ValidationError.error, got \(error)")
        return
      }
      XCTAssertTrue(reason.contains("authFlowRedirectionURI must be provided"))
    }
  }

  func testConfigWithBothGrantsRequiresRedirectionURI() throws {
    XCTAssertThrowsError(
      try OpenId4VCIConfig(
        client: .public(id: "test-client"),
        authFlowRedirectionURI: nil,
        supportedGrants: .both
      )
    ) { error in
      guard case ValidationError.error(let reason) = error else {
        XCTFail("Expected ValidationError.error, got \(error)")
        return
      }
      XCTAssertTrue(reason.contains("authFlowRedirectionURI must be provided"))
    }
  }

  func testConfigWithPreAuthorizedCodeGrantsDoesNotRequireRedirectionURI() throws {
    let config = try OpenId4VCIConfig(
      client: .public(id: "test-client"),
      authFlowRedirectionURI: nil,
      supportedGrants: .preAuthorizedCode
    )

    XCTAssertNil(config.authFlowRedirectionURI)
    XCTAssertEqual(config.supportedGrants, SupportedGrants.preAuthorizedCode)
  }

  func testConfigWithAuthorizationCodeGrantsAndRedirectionURISucceeds() throws {
    let redirectURI = URL(string: "https://example.com/callback")!
    let config = try OpenId4VCIConfig(
      client: .public(id: "test-client"),
      authFlowRedirectionURI: redirectURI,
      supportedGrants: .authorizationCode
    )

    XCTAssertEqual(config.authFlowRedirectionURI, redirectURI)
    XCTAssertEqual(config.supportedGrants, SupportedGrants.authorizationCode)
  }

  func testConfigWithBothGrantsAndRedirectionURISucceeds() throws {
    let redirectURI = URL(string: "https://example.com/callback")!
    let config = try OpenId4VCIConfig(
      client: .public(id: "test-client"),
      authFlowRedirectionURI: redirectURI,
      supportedGrants: .both
    )

    XCTAssertEqual(config.authFlowRedirectionURI, redirectURI)
    XCTAssertEqual(config.supportedGrants, SupportedGrants.both)
  }

  // MARK: - CredentialOfferRequestValidationError.unsupportedGrants Tests

  func testUnsupportedGrantsErrorContainsReason() {
    let underlyingError = ValidationError.error(reason: "Test underlying error")
    let error = CredentialOfferRequestValidationError.unsupportedGrants(reason: underlyingError)

    if case .unsupportedGrants(let reason) = error {
      XCTAssertTrue(reason.localizedDescription.contains("Test underlying error"))
    } else {
      XCTFail("Expected unsupportedGrants error")
    }
  }

  // MARK: - Credential Offer JSON Parsing with Grants Validation

  func testCredentialOfferWithAuthorizationCodeOnlyGrant() throws {
    let json = """
    {
       "credential_issuer": "https://credential-issuer.example.com",
       "credential_configuration_ids": ["UniversityDegree_JWT"],
       "grants": {
          "authorization_code": {
             "issuer_state": "eyJhbGciOiJSU0Et...FYUaBy"
          }
       }
    }
    """.removeWhitespaceAndNewlines()

    let urlString = "https://example.com/?credential_offer=\(json)"
    let request = try CredentialOfferRequest(urlString: urlString)

    switch request {
    case .passByValue(let metaData):
      if let requestObject = CredentialOfferRequestObject(jsonString: metaData) {
        let grants = try requestObject.grants?.toDomain()

        // Verify it's an authorization code grant
        if case .authorizationCode(let authCode) = grants {
          XCTAssertEqual(authCode.issuerState, "eyJhbGciOiJSU0Et...FYUaBy")

          // Wallet with authorizationCode support should support this
          XCTAssertTrue(SupportedGrants.authorizationCode.supports(grants!))
          XCTAssertTrue(SupportedGrants.both.supports(grants!))

          // Wallet with only preAuthorizedCode should NOT support this
          XCTAssertFalse(SupportedGrants.preAuthorizedCode.supports(grants!))
        } else {
          XCTFail("Expected authorization_code grant")
        }
      } else {
        XCTFail("Failed to parse credential offer request object")
      }
    default:
      XCTFail("Expected .passByValue")
    }
  }

  func testCredentialOfferWithPreAuthorizedCodeOnlyGrant() throws {
    let json = """
    {
       "credential_issuer": "https://credential-issuer.example.com",
       "credential_configuration_ids": ["UniversityDegree_JWT"],
       "grants": {
          "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
             "pre-authorized_code": "adhjhdjajkdkhjhdj"
          }
       }
    }
    """.removeWhitespaceAndNewlines()

    let urlString = "https://example.com/?credential_offer=\(json)"
    let request = try CredentialOfferRequest(urlString: urlString)

    switch request {
    case .passByValue(let metaData):
      if let requestObject = CredentialOfferRequestObject(jsonString: metaData) {
        let grants = try requestObject.grants?.toDomain()

        // Verify it's a pre-authorized code grant
        if case .preAuthorizedCode(let preAuthCode) = grants {
          XCTAssertEqual(preAuthCode.preAuthorizedCode, "adhjhdjajkdkhjhdj")

          // Wallet with preAuthorizedCode support should support this
          XCTAssertTrue(SupportedGrants.preAuthorizedCode.supports(grants!))
          XCTAssertTrue(SupportedGrants.both.supports(grants!))

          // Wallet with only authorizationCode should NOT support this
          XCTAssertFalse(SupportedGrants.authorizationCode.supports(grants!))
        } else {
          XCTFail("Expected pre-authorized_code grant")
        }
      } else {
        XCTFail("Failed to parse credential offer request object")
      }
    default:
      XCTFail("Expected .passByValue")
    }
  }

  func testCredentialOfferWithBothGrants() throws {
    let json = """
    {
       "credential_issuer": "https://credential-issuer.example.com",
       "credential_configuration_ids": ["UniversityDegree_JWT"],
       "grants": {
          "authorization_code": {
             "issuer_state": "eyJhbGciOiJSU0Et...FYUaBy"
          },
          "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
             "pre-authorized_code": "adhjhdjajkdkhjhdj"
          }
       }
    }
    """.removeWhitespaceAndNewlines()

    let urlString = "https://example.com/?credential_offer=\(json)"
    let request = try CredentialOfferRequest(urlString: urlString)

    switch request {
    case .passByValue(let metaData):
      if let requestObject = CredentialOfferRequestObject(jsonString: metaData) {
        let grants = try requestObject.grants?.toDomain()

        // Verify it contains both grants
        if case .both(let authCode, let preAuthCode) = grants {
          XCTAssertEqual(authCode.issuerState, "eyJhbGciOiJSU0Et...FYUaBy")
          XCTAssertEqual(preAuthCode.preAuthorizedCode, "adhjhdjajkdkhjhdj")

          // All wallet configurations should support "both" grants
          XCTAssertTrue(SupportedGrants.authorizationCode.supports(grants!))
          XCTAssertTrue(SupportedGrants.preAuthorizedCode.supports(grants!))
          XCTAssertTrue(SupportedGrants.both.supports(grants!))
        } else {
          XCTFail("Expected both grants")
        }
      } else {
        XCTFail("Failed to parse credential offer request object")
      }
    default:
      XCTFail("Expected .passByValue")
    }
  }
}
