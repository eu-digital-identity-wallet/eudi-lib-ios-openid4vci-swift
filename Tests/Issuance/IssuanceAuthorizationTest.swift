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
import JOSESwift

@testable import OpenID4VCI

class IssuanceAuthorizationTest: XCTestCase {
  
  let config: OpenId4VCIConfig = .init(
    clientId: "wallet-dev",
    authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!,
    authorizeIssuanceConfig: .favorScopes
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
    let parPlaced = try await issuer.pushAuthorizationCodeRequest(
      credentialOffer: offer
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
    let parPlaced = try await issuer.pushAuthorizationCodeRequest(
      credentialOffer: offer
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
         case let .noProofRequired(token, _, _) = authorized {
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
         case let .proofRequired(token, _, _, _) = authorized {
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
  
  func testSuccessfulAuthorizationWithPreAuthorizationCodeFlow() async throws {
    
    // Given
    guard let offer = await TestsConstants.createMockPreAuthCredentialOffer() else {
      XCTAssert(false, "Unable to resolve credential offer")
      return
    }
    
    // When
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: config,
      parPoster: Poster(
        session: NetworkingThrowingMock()
      ),
      tokenPoster: Poster(
        session: NetworkingMock(
          path: "access_token_request_response_no_proof",
          extension: "json"
        )
      )
    )
    
    let grants = offer.grants
    var code: Grants.PreAuthorizedCode!
    switch grants {
    case .preAuthorizedCode(let preAuthorizedCode):
      code = preAuthorizedCode
    case .both(_, let preAuthorizedCode):
      code = preAuthorizedCode
    default:
      XCTAssert(false, "Unexpected grant type")
    }
    
    let result = await issuer.authorizeWithPreAuthorizationCode(
      credentialOffer: offer,
      authorizationCode: try .init(
        preAuthorizationCode: code.preAuthorizedCode,
        txCode: code.txCode
      ),
      clientId: "218232426",
      transactionCode: "123456"
    )
    
    switch result {
    case .success(let request):
      if case let .noProofRequired(token, _, _) = request {
        XCTAssert(true, "Got access token: \(token)")
      }
    case .failure(let error):
      XCTAssert(false, error.localizedDescription)
    }
  }
  
  func testThirdPartyIssuerSuccessfulAuthorizationWithPreAuthorizationCodeFlow() async throws {
    
    /// Replace the url string below with the one you can generate here: https://trial.authlete.net/api/offer/issue
    let urlString = """
    """
    
    if urlString.isEmpty {
      XCTExpectFailure()
      XCTAssert(false, "urlString cannot be empty")
      return
    }
    
    let resolver = CredentialOfferRequestResolver()
    let resolution = await resolver
      .resolve(
        source: try .init(
          urlString: urlString
        )
      )
    
    let offer: CredentialOffer = try resolution.get()
    let issuerMetadata = offer.credentialIssuerMetadata
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: issuerMetadata,
      config: config
    )
    
    let grants = offer.grants
    var code: Grants.PreAuthorizedCode!
    switch grants {
    case .preAuthorizedCode(let preAuthorizedCode):
      code = preAuthorizedCode
    case .both(_, let preAuthorizedCode):
      code = preAuthorizedCode
    default:
      XCTAssert(false, "Unexpected grant type")
    }
    
    let result = await issuer.authorizeWithPreAuthorizationCode(
      credentialOffer: offer,
      authorizationCode: try .init(
        preAuthorizationCode: code.preAuthorizedCode,
        txCode: code.txCode
      ),
      clientId: "218232426",
      transactionCode: "12345"
    )
    
    let privateKey = try KeyController.generateRSAPrivateKey()
    let publicKey = try KeyController.generateRSAPublicKey(from: privateKey)
    
    let alg = JWSAlgorithm(.RS256)
    let publicKeyJWK = try RSAPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "alg": alg.name,
        "use": "sig",
        "kid": UUID().uuidString
      ])
    
    let bindingKey: BindingKey = .jwk(
      algorithm: alg,
      jwk: publicKeyJWK,
      privateKey: privateKey,
      issuer: "218232426"
    )
    
    let request = try result.get()
    let payload: IssuanceRequestPayload = .configurationBased(
      credentialConfigurationIdentifier: try CredentialConfigurationIdentifier(
        value: "IdentityCredential"
      ),
      claimSet: nil
    )
    
    let requestSingleResult = try await issuer.requestSingle(
      proofRequest: request,
      bindingKey: bindingKey,
      requestPayload: payload,
      responseEncryptionSpecProvider: {
        Issuer.createResponseEncryptionSpec($0)
      })
    
    switch requestSingleResult {
    case .success(let request):
      print(request.credentials.joined(separator: ", "))
      XCTAssertTrue(true)
    case .failure(let error):
      XCTAssert(false, error.localizedDescription)
    }
  }
  
  func testThirdPartyIssuerSuccessfulAuthorizationWithPreAuthorizationCodeFlowWithDPoP() async throws {
    
    /// Replace the url string below with the one you can generate here: https://trial.authlete.net/api/offer/issue
    let urlString = """
    """
    if urlString.isEmpty {
      XCTExpectFailure()
      XCTAssert(false, "urlString cannot be empty")
      return
    }
    
    let resolver = CredentialOfferRequestResolver()
    let resolution = await resolver
      .resolve(
        source: try .init(
          urlString: urlString
        )
      )
    
    let privateKey = try KeyController.generateECDHPrivateKey()
    let publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
    
    let alg = JWSAlgorithm(.ES256)
    let jwk = try ECPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "alg": alg.name,
        "use": "sig",
        "kid": UUID().uuidString
      ])
    
    let dpopConstructor: DPoPConstructor = .init(
      algorithm: alg,
      jwk: jwk,
      privateKey: privateKey
    )
    
    let offer: CredentialOffer = try resolution.get()
    let issuerMetadata = offer.credentialIssuerMetadata
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: issuerMetadata,
      config: config,
      dpopConstructor: dpopConstructor
    )
    
    let grants = offer.grants
    var code: Grants.PreAuthorizedCode!
    switch grants {
    case .preAuthorizedCode(let preAuthorizedCode):
      code = preAuthorizedCode
    case .both(_, let preAuthorizedCode):
      code = preAuthorizedCode
    default:
      XCTAssert(false, "Unexpected grant type")
    }
    
    let result = await issuer.authorizeWithPreAuthorizationCode(
      credentialOffer: offer,
      authorizationCode: try .init(
        preAuthorizationCode: code.preAuthorizedCode,
        txCode: code.txCode
      ),
      clientId: "218232426",
      transactionCode: "12345"
    )
    
    let bindingKey: BindingKey = .jwk(
      algorithm: alg,
      jwk: jwk,
      privateKey: privateKey,
      issuer: "218232426"
    )
    
    let request = try result.get()
    let payload: IssuanceRequestPayload = .configurationBased(
      credentialConfigurationIdentifier: try CredentialConfigurationIdentifier(
        value: "IdentityCredential"
      ),
      claimSet: nil
    )
    
    let requestSingleResult = try await issuer.requestSingle(
      proofRequest: request,
      bindingKey: bindingKey,
      requestPayload: payload,
      responseEncryptionSpecProvider: {
        Issuer.createResponseEncryptionSpec($0)
      })
    
    switch requestSingleResult {
    case .success(let request):
      print(request.credentials.joined(separator: ", "))
      XCTAssertTrue(true)
    case .failure(let error):
      XCTAssert(false, error.localizedDescription)
    }
  }
}

