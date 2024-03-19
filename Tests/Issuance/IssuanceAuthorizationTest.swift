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

class IssuanceAuthorizationTest: XCTestCase {
  
  let config: WalletOpenId4VCIConfig = .init(
    clientId: "wallet-dev",
    authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!
  )
  
  override func setUp() async throws {
    try await super.setUp()
  }
  
  override func tearDown() {
    super.tearDown()
  }
  
  func testPushAuthorizationCodeRequestPlacementSuccesful() async throws {
    
    // Given
    guard let offer = await TestsConstants.createMockCredentialOffer() else {
      XCTAssert(false, "Unable to resolve credential offer")
      return
    }
    
    // When
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: config,
      parPoster: Poster(
        session: NetworkingMock(
          path: "pushed_authorization_request_response",
          extension: "json"
        )
      )
    )
    
    // Then
    let parPlaced = await issuer.pushAuthorizationCodeRequest(
      credentials: offer.credentialConfigurationIdentifiers
    )

    if case let .success(request) = parPlaced,
       case let .par(parRequested) = request {
      let requestUrl = parRequested.getAuthorizationCodeURL.url.queryParameters["request_uri"]
      XCTAssertNotNil(requestUrl)
    } else {
      XCTAssert(false, "parRequested failed")
    }
  }
  
  func testPushAuthorizationCodeRequestPlacementFailed() async throws {
    
    // Given
    guard let offer = await TestsConstants.createMockCredentialOffer() else {
      XCTAssert(false, "Unable to resolve credential offer")
      return
    }
    
    // When
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: config,
      parPoster: Poster(
        session: NetworkingMock(
          path: "test",
          extension: "json"
        )
      )
    )
    
    // Then
    let parPlaced = await issuer.pushAuthorizationCodeRequest(
      credentials: offer.credentialConfigurationIdentifiers
    )

    switch parPlaced {
    case .success:
      XCTAssert(false, "Expected failure")
    case .failure(let error):
      XCTAssertTrue(true, error.localizedDescription)
    }
  }
  
  func testAccessTokenAquisitionNoProofRequiredSuccess() async throws {
    
    // Given
    guard let offer = await TestsConstants.createMockCredentialOffer() else {
      XCTAssert(false, "Unable to resolve credential offer")
      return
    }
    
    // When
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: config,
      parPoster: Poster(
        session: NetworkingMock(
          path: "pushed_authorization_request_response",
          extension: "json"
        )
      ),
      tokenPoster: Poster(
        session: NetworkingMock(
          path: "access_token_request_response_no_proof",
          extension: "json"
        )
      )
    )
    
    let authorizationCode = "MZqG9bsQ8UALhsGNlY39Yw=="
    let request: UnauthorizedRequest = TestsConstants.unAuthorizedRequest
    
    let issuanceAuthorization: IssuanceAuthorization = .authorizationCode(authorizationCode: authorizationCode)
    let unAuthorized = await issuer.handleAuthorizationCode(
      parRequested: request,
      authorizationCode: issuanceAuthorization
    )
    
    switch unAuthorized {
    case .success(let authorizationCode):
      let authorizedRequest = await issuer.requestAccessToken(authorizationCode: authorizationCode)
      
      if case let .success(authorized) = authorizedRequest,
         case let .noProofRequired(token, _) = authorized {
        XCTAssert(true, "Got access token: \(token)")
        return
      }
      
    case .failure(let error):
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(false, "Unable to get access token")
  }
  
  func testAccessTokenAquisitionProofRequiredSuccess() async throws {
    
    // Given
    guard let offer = await TestsConstants.createMockCredentialOffer() else {
      XCTAssert(false, "Unable to resolve credential offer")
      return
    }
    
    // When
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: config,
      parPoster: Poster(
        session: NetworkingMock(
          path: "pushed_authorization_request_response",
          extension: "json"
        )
      ),
      tokenPoster: Poster(
        session: NetworkingMock(
          path: "access_token_request_response",
          extension: "json"
        )
      )
    )
    
    let request: UnauthorizedRequest = TestsConstants.unAuthorizedRequest
    
    let authorizationCode = "MZqG9bsQ8UALhsGNlY39Yw=="
    let issuanceAuthorization: IssuanceAuthorization = .authorizationCode(authorizationCode: authorizationCode)
    let unAuthorized = await issuer.handleAuthorizationCode(
      parRequested: request,
      authorizationCode: issuanceAuthorization
    )
    
    switch unAuthorized {
    case .success(let authorizationCode):
      let authorizedRequest = await issuer.requestAccessToken(authorizationCode: authorizationCode)
      
      if case let .success(authorized) = authorizedRequest,
         case let .proofRequired(token, _, _) = authorized {
        XCTAssert(true, "Got access token: \(token)")
        return
      }
      
    case .failure(let error):
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(false, "Unable to get access token")
  }
  
  func testAccessTokenAquisitionProofRequiredFailure() async throws {
    
    // Given
    guard let offer = await TestsConstants.createMockCredentialOffer() else {
      XCTAssert(false, "Unable to resolve credential offer")
      return
    }
    
    // When
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: config,
      parPoster: Poster(
        session: NetworkingMock(
          path: "pushed_authorization_request_response",
          extension: "json"
        )
      ),
      tokenPoster: Poster(
        session: NetworkingMock(
          path: "test",
          extension: "json"
        )
      )
    )
    
    let request: UnauthorizedRequest = TestsConstants.unAuthorizedRequest
    
    let authorizationCode = "MZqG9bsQ8UALhsGNlY39Yw=="
    let issuanceAuthorization: IssuanceAuthorization = .authorizationCode(authorizationCode: authorizationCode)
    let unAuthorized = await issuer.handleAuthorizationCode(
      parRequested: request,
      authorizationCode: issuanceAuthorization
    )
    
    switch unAuthorized {
    case .success(let authorizationCode):
      let authorizedRequest = await issuer.requestAccessToken(authorizationCode: authorizationCode)
      
      switch authorizedRequest {
      case .success:
        XCTAssert(false, "Did not expect success")
      case .failure(let error):
        XCTAssert(true, "Got expected failure: \(error.localizedDescription)")
      }
      return
      
    case .failure(let error):
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(false, "Unable to get access token")
  }
}

