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

class IssuanceDeferredRequestTest: XCTestCase {
  
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
  
  func testWhenIssuerRespondsDefferredThenTransactionIdExists() async throws {
    
    // Given
    guard let offer = await TestsConstants.createMockCredentialOfferValidEncryption() else {
      XCTAssert(false, "Unable to resolve credential offer")
      return
    }
    
    let privateKey = try KeyController.generateRSAPrivateKey()
    let publicKey = try KeyController.generateRSAPublicKey(from: privateKey)
    
    let alg = JWSAlgorithm(.RS256)
    let publicKeyJWK = try RSAPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "alg": alg.name,
        "use": "enc",
        "kid": UUID().uuidString
      ])
    
    let spec = IssuanceResponseEncryptionSpec(
      jwk: publicKeyJWK,
      privateKey: privateKey,
      algorithm: .init(.RSA_OAEP_256),
      encryptionMethod: .init(.A128CBC_HS256)
    )
    
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
      requesterPoster: Poster(
        session: NetworkingMock(
          path: "single_issuance_success_response_deffered",
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
         case let .noProofRequired(token, _, _, _) = authorized {
        XCTAssert(true, "Got access token: \(token)")
        XCTAssert(true, "Is no proof required")
        
        do {
          let payload: IssuanceRequestPayload = .configurationBased(
            credentialConfigurationIdentifier: try .init(
              value: "eu.europa.ec.eudi.pid_mso_mdoc"
            ),
            claimSet: nil
          )
          let result = try await issuer.requestSingle(
            noProofRequest: authorized,
            requestPayload: payload,
            responseEncryptionSpecProvider: { _ in
              spec
            })
          
          switch result {
          case .success(let request):
            switch request {
            case .success(let response):
              if let result = response.credentialResponses.first {
                switch result {
                case .deferred(let transactionId):
                  XCTAssert(true, "transaction_id: \(transactionId)")
                  return
                case .issued(_, let credential, _):
                  XCTAssert(false, "credential: \(credential)")
                }
              } else {
                XCTAssert(false, "No response")
              }
            case .failed(let error):
              XCTAssert(false, "failed: \(error.localizedDescription)")
              
            case .invalidProof:
              XCTAssert(false, ".invalidProof")
            }
            XCTAssert(false, "Unexpected request")
          case .failure(let error):
            XCTAssert(false, error.localizedDescription)
          }
        } catch {
          XCTAssert(false, error.localizedDescription)
        }
      }
    case .failure(let error):
      XCTAssert(false, error.localizedDescription)
    }
  }
}
