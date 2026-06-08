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

class IssuanceRefreshTokenTest: XCTestCase {

  let config: OpenId4VCIConfig = .init(
    client: publicClient,
    authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!,
    authorizeIssuanceConfig: .favorScopes
  )

  func testManualRefreshAccessTokenSuccess() async throws {

    // Given
    guard let offer = await TestsConstants.createMockCredentialOffer() else {
      XCTFail("Unable to resolve credential offer")
      return
    }

    // Create mock authorized request with refresh token
    let originalAccessToken = try IssuanceAccessToken(
      accessToken: "original_access_token",
      tokenType: .init(value: "Bearer")
    )
    let refreshToken = try IssuanceRefreshToken(
      refreshToken: "refresh_token_value",
      expiresIn: 3600
    )
    let originalRequest = AuthorizedRequest(
      accessToken: originalAccessToken,
      refreshToken: refreshToken,
      credentialIdentifiers: nil,
      timeStamp: Date().timeIntervalSince1970,
      dPopNonce: nil,
      grantType: .authorizationCode
    )

    // Create issuer with mock token endpoint
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: config,
      tokenPoster: Poster(
        session: NetworkingMock(
          path: "access_token_request_response",
          extension: "json"
        )
      )
    )

    // When - using the new simplified refresh method
    do {
      let refreshedRequest = try await issuer.refresh(
        authorizedRequest: originalRequest
      )

      // Then
      XCTAssertNotNil(refreshedRequest.accessToken)
      XCTAssertNotEqual(
        refreshedRequest.accessToken.accessToken,
        originalRequest.accessToken.accessToken,
        "Access token should be refreshed"
      )
      XCTAssertNotEqual(
        refreshedRequest.timeStamp,
        originalRequest.timeStamp,
        "Timestamp should be updated"
      )
    } catch {
      XCTFail("Token refresh failed: \(error.localizedDescription)")
    }
  }

  func testManualRefreshWithoutRefreshTokenReturnsOriginal() async throws {

    // Given
    guard let offer = await TestsConstants.createMockCredentialOffer() else {
      XCTFail("Unable to resolve credential offer")
      return
    }

    // Create authorized request WITHOUT refresh token
    let originalAccessToken = try IssuanceAccessToken(
      accessToken: "original_access_token",
      tokenType: .init(value: "Bearer")
    )
    let originalRequest = AuthorizedRequest(
      accessToken: originalAccessToken,
      refreshToken: nil,  // No refresh token
      credentialIdentifiers: nil,
      timeStamp: Date().timeIntervalSince1970,
      dPopNonce: nil,
      grantType: .authorizationCode
    )

    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: config
    )

    // When
    let refreshedRequest = try await issuer.refresh(
      authorizedRequest: originalRequest
    )

    // Then - should return original request unchanged
    XCTAssertEqual(
      refreshedRequest.accessToken.accessToken,
      originalRequest.accessToken.accessToken,
      "Access token should remain unchanged when no refresh token is present"
    )
    XCTAssertEqual(
      refreshedRequest.timeStamp,
      originalRequest.timeStamp,
      "Timestamp should remain unchanged when no refresh token is present"
    )
  }

  func testManualRefreshWithDPoPNonce() async throws {

    // Given
    guard let offer = await TestsConstants.createMockCredentialOffer() else {
      XCTFail("Unable to resolve credential offer")
      return
    }

    let originalAccessToken = try IssuanceAccessToken(
      accessToken: "original_access_token",
      tokenType: .init(value: "Bearer")
    )
    let refreshToken = try IssuanceRefreshToken(
      refreshToken: "refresh_token_value",
      expiresIn: 3600
    )
    let originalRequest = AuthorizedRequest(
      accessToken: originalAccessToken,
      refreshToken: refreshToken,
      credentialIdentifiers: nil,
      timeStamp: Date().timeIntervalSince1970,
      dPopNonce: nil,
      grantType: .authorizationCode
    )

    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: config,
      tokenPoster: Poster(
        session: NetworkingMock(
          path: "access_token_request_response",
          extension: "json"
        )
      )
    )

    let dpopNonce = Nonce(value: "test_dpop_nonce")

    // When - using refresh with explicit DPoP nonce
    do {
      let refreshedRequest = try await issuer.refresh(
        authorizedRequest: originalRequest,
        dPopNonce: dpopNonce
      )

      // Then
      XCTAssertNotNil(refreshedRequest.accessToken)
      // The refresh should succeed even with a DPoP nonce parameter
    } catch {
      XCTFail("Token refresh with DPoP nonce failed: \(error.localizedDescription)")
    }
  }
}
