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
    client: .public(id: WALLET_DEV_CLIENT_ID),
    authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!,
    authorizeIssuanceConfig: .favorScopes
  )
  
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
      ),
      dpopConstructor: dpopConstructor(
        algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported
      )
    )
    
    // Then
    let parPlaced = try await issuer.prepareAuthorizationRequest(
      credentialOffer: offer
    )

    if case let .success(request) = parPlaced,
       case let .prepared(parRequested) = request {
      let requestUrl = parRequested.authorizationCodeURL.url.queryParameters["request_uri"]
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
      ),
      dpopConstructor: dpopConstructor(
        algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported
      )
    )
    
    // Then
    let parPlaced = try await issuer.prepareAuthorizationRequest(
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
      ),
      dpopConstructor: dpopConstructor(
        algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported
      )
    )
    
    let authorizationCode = "MZqG9bsQ8UALhsGNlY39Yw=="
    let request: AuthorizationRequestPrepared = TestsConstants.unAuthorizedRequest
    
    let issuanceAuthorization: IssuanceAuthorization = .authorizationCode(authorizationCode: authorizationCode)
    let unAuthorized = await issuer.handleAuthorizationCode(
      request: request,
      authorizationCode: issuanceAuthorization
    )
    
    switch unAuthorized {
    case .success(let authorizationCode):
      let authorizedRequest = await issuer.authorizeWithAuthorizationCode(request: authorizationCode)
      
      if case let .success(authorized) = authorizedRequest {
        XCTAssert(true, "Got access token: \(authorized.accessToken)")
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
      ),
      dpopConstructor: dpopConstructor(
        algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported
      )
    )
    
    let request: AuthorizationRequestPrepared = TestsConstants.unAuthorizedRequest
    
    let authorizationCode = "MZqG9bsQ8UALhsGNlY39Yw=="
    let issuanceAuthorization: IssuanceAuthorization = .authorizationCode(authorizationCode: authorizationCode)
    let unAuthorized = await issuer.handleAuthorizationCode(
      request: request,
      authorizationCode: issuanceAuthorization
    )
    
    switch unAuthorized {
    case .success(let authorizationCode):
      let authorizedRequest = await issuer.authorizeWithAuthorizationCode(request: authorizationCode)
      if case let .success(authorized) = authorizedRequest {
        XCTAssert(true, "Got access token: \(authorized.accessToken)")
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
      ),
      dpopConstructor: dpopConstructor(
        algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported
      )
    )
    
    let request: AuthorizationRequestPrepared = TestsConstants.unAuthorizedRequest
    
    let authorizationCode = "MZqG9bsQ8UALhsGNlY39Yw=="
    let issuanceAuthorization: IssuanceAuthorization = .authorizationCode(authorizationCode: authorizationCode)
    let unAuthorized = await issuer.handleAuthorizationCode(
      request: request,
      authorizationCode: issuanceAuthorization
    )
    
    switch unAuthorized {
    case .success(let authorizationCode):
      let authorizedRequest = await issuer.authorizeWithAuthorizationCode(request: authorizationCode)
      
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
      ),
      dpopConstructor: dpopConstructor(
        algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported
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
      client: .public(id: "218232426"),
      transactionCode: "123456"
    )
    
    switch result {
    case .success(let request):
      XCTAssert(true, "Got access token: \(request.accessToken)")
    case .failure(let error):
      XCTAssert(false, error.localizedDescription)
    }
  }
  
  func testThirdPartyIssuerSuccessfulAuthorizationWithPreAuthorizationCodeFlow() async throws {
    
    /// Replace the url string below with the one you can generate here: https://trial.authlete.net/api/offer/issue
    /// login/pass: inga (for both)
    /// Credential Configuration IDs: Just leave "IdentityCredential"
    /// Authorization Code Grant: unchecked
    /// Pre-Authorized Code Grant: check
    ///   Value: 12345
    ///   Input Mode: numeric
    ///   Description: "hello world"
    ///
    /// Submit
    ///
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
        ),
        policy: .ignoreSigned
      )
    
    let offer: CredentialOffer = try resolution.get()
    let issuerMetadata = offer.credentialIssuerMetadata
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: issuerMetadata,
      config: config,
      dpopConstructor: dpopConstructor(
        algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported
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
      client: .public(id: "218232426"),
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
    
    let bindingKey: BindingKey = .jwt(
      algorithm: alg,
      jwk: publicKeyJWK,
      privateKey: .secKey(privateKey),
      issuer: "218232426"
    )
    
    let request = try result.get()
    let payload: IssuanceRequestPayload = .configurationBased(
      credentialConfigurationIdentifier: try CredentialConfigurationIdentifier(
        value: "org.iso.18013.5.1.mDL"
      )
    )
    
    let requestSingleResult = try await issuer.requestCredential(
      request: request,
      bindingKeys: [bindingKey],
      requestPayload: payload,
      responseEncryptionSpecProvider: {
        Issuer.createResponseEncryptionSpec($0)
      }
    )

    switch requestSingleResult {
    case .success(let request):
      switch request {
      case .success(let response):
        print(response.credentialResponses.map { try! $0.toDictionary() })
        XCTAssertTrue(true)
      default:
        XCTAssert(false, "Unexpected request type")
      }
    case .failure(let error):
      XCTAssert(false, error.localizedDescription)
    }
  }
  
  func testThirdPartyIssuerSuccessfulAuthorizationWithPreAuthorizationCodeFlowAttested() async throws {
    
    /// Replace the url string below with the one you can generate here: https://trial.authlete.net/api/offer/issue
    /// login/pass: inga (for both)
    /// Credential Configuration IDs: Just leave "IdentityCredential"
    /// Authorization Code Grant: unchecked
    /// Pre-Authorized Code Grant: check
    ///   Value: 12345
    ///   Input Mode: numeric
    ///   Description: "hello world"
    ///
    /// Submit
    ///
    let urlString = """
    """
    
    if urlString.isEmpty {
      XCTExpectFailure()
      XCTAssert(false, "urlString cannot be empty")
      return
    }
    
    let privateKey = try KeyController.generateRSAPrivateKey()
    let publicKey = try KeyController.generateRSAPublicKey(from: privateKey)
    let privateKeyProxy: SigningKeyProxy = .secKey(privateKey)
    
    let alg = JWSAlgorithm(.RS256)
    let publicKeyJWK = try RSAPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "alg": alg.name,
        "use": "sig",
        "kid": UUID().uuidString
      ])
    
    let bindingKey: BindingKey = .jwt(
      algorithm: alg,
      jwk: publicKeyJWK,
      privateKey: privateKeyProxy,
      issuer: "track2_full"
    )
    
    let resolver = CredentialOfferRequestResolver()
    let resolution = await resolver
      .resolve(
        source: try .init(
          urlString: urlString
        ),
        policy: .ignoreSigned
      )
    
    let attestationConfig: OpenId4VCIConfig = .init(
      client: try! selfSignedClient(
        clientId: "track2_full",
        privateKey: try KeyController.generateECDHPrivateKey()
      ),
      authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!,
      authorizeIssuanceConfig: .favorScopes,
      clientAttestationPoPBuilder: DefaultClientAttestationPoPBuilder()
    )
    
    let offer: CredentialOffer = try resolution.get()
    let issuerMetadata = offer.credentialIssuerMetadata
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: issuerMetadata,
      config: attestationConfig,
      dpopConstructor: dpopConstructor(
        algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported
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
      client: attestationConfig.client,
      transactionCode: "12345",
      authorizationDetailsInTokenRequest: .include(filter: { _ in true })
    )
    
    switch result {
    case .success:
      let request = try result.get()
      let payload: IssuanceRequestPayload = .configurationBased(
        credentialConfigurationIdentifier: try CredentialConfigurationIdentifier(
          value: "org.iso.18013.5.1.mDL"
        )
      )
      
      let requestSingleResult = try await issuer.requestCredential(
        request: request,
        bindingKeys: [bindingKey],
        requestPayload: payload,
        responseEncryptionSpecProvider: {
          Issuer.createResponseEncryptionSpec($0)
        }
      )

      switch requestSingleResult {
      case .success(let request):
        switch request {
        case .success(let response):
          print(response.credentialResponses.map { try! $0.toDictionary() })
          XCTAssertTrue(true)
        default:
          XCTAssert(false, "Unexpected request type")
        }
      case .failure(let error):
        XCTAssert(false, error.localizedDescription)
      }
    case .failure:
      XCTAssert(false)
    }
  }
  
  func testTestIssuerSuccessfulAuthorizationWithPreAuthorizationCodeFlow() async throws {

    /// Replace the url string below with the one you can generate here: https://dev.tester.issuer.eudiw.dev/
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
        ),
        policy: .ignoreSigned
      )

    let offer: CredentialOffer = try resolution.get()
    let issuerMetadata = offer.credentialIssuerMetadata
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: issuerMetadata,
      config: config,
      dpopConstructor: dpopConstructor(
        algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported
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

    /// Change the transaction code with the one obtained https://dev.tester.issuer.eudiw.dev/
    let result = await issuer.authorizeWithPreAuthorizationCode(
      credentialOffer: offer,
      authorizationCode: try .init(
        preAuthorizationCode: code.preAuthorizedCode,
        txCode: code.txCode
      ),
      client: .public(id: WALLET_DEV_CLIENT_ID),
      transactionCode: "12345"
    )

    let privateKey = try KeyController.generateECDHPrivateKey()
    let publicKey = try KeyController.generateECDHPublicKey(from: privateKey)

    let alg = JWSAlgorithm(.ES256)
    let publicKeyJWK = try ECPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "alg": alg.name,
        "use": "sig",
        "kid": UUID().uuidString
    ])

    let bindingKey: BindingKey = .jwt(
      algorithm: alg,
      jwk: publicKeyJWK,
      privateKey: .secKey(privateKey),
      issuer: "218232426"
    )

    let request = try result.get()
    let payload: IssuanceRequestPayload = .configurationBased(
      credentialConfigurationIdentifier: try CredentialConfigurationIdentifier(
        value: offer.credentialConfigurationIdentifiers.first!.value
      )
    )

    let requestSingleResult = try await issuer.requestCredential(
      request: request,
      bindingKeys: [bindingKey],
      requestPayload: payload,
      responseEncryptionSpecProvider: {
        Issuer.createResponseEncryptionSpec($0)
    })

    switch requestSingleResult {
    case .success(let request):
      switch request {
      case .success(let response):
        print(response.credentialResponses.map { try! $0.toDictionary() })
        XCTAssertTrue(true)
      default:
        XCTAssert(false, "Unexpected request type")
      }
    case .failure(let error):
      XCTAssert(false, error.localizedDescription)
    }
  }

  func testThirdPartyIssuerSuccessfulAuthorizationWithPreAuthorizationCodeFlowWithDPoP() async throws {
    
    /// Replace the url string below with the one you can generate here: https://trial.authlete.net/api/offer/issue
    /// login/pass: inga (for both)
    /// Credential Configuration IDs: Just leave "IdentityCredential"
    /// Authorization Code Grant: unchecked
    /// Pre-Authorized Code Grant: check
    ///   Value: 12345
    ///   Input Mode: numeric
    ///   Description: "hello world"
    ///
    /// Submit
    ///
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
        ),
        policy: .ignoreSigned
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
    
    let offer: CredentialOffer = try resolution.get()
    let issuerMetadata = offer.credentialIssuerMetadata
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: issuerMetadata,
      config: config,
      dpopConstructor: dpopConstructor(
        algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported
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
      client: .public(id: "218232426"),
      transactionCode: "12345"
    )
    
    let bindingKey: BindingKey = .jwt(
      algorithm: alg,
      jwk: jwk,
      privateKey: .secKey(privateKey),
      issuer: "218232426"
    )
    
    let request = try result.get()
    let payload: IssuanceRequestPayload = .configurationBased(
      credentialConfigurationIdentifier: try CredentialConfigurationIdentifier(
        value: "IdentityCredential"
      )
    )
    
    let requestSingleResult = try await issuer.requestCredential(
      request: request,
      bindingKeys: [bindingKey],
      requestPayload: payload,
      responseEncryptionSpecProvider: {
        Issuer.createResponseEncryptionSpec($0)
      })
    
    switch requestSingleResult {
    case .success(let request):
      switch request {
      case .success(let response):
        print(response.credentialResponses.map { try! $0.toDictionary() })
        XCTAssertTrue(true)
      default:
        XCTAssert(false, "Unexpected request type")
      }
    case .failure(let error):
      XCTAssert(false, error.localizedDescription)
    }
  }
}
