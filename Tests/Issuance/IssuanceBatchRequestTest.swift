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
import SwiftyJSON

@testable import OpenID4VCI

class IssuanceBatchRequestTest: XCTestCase {
  
  let config: OpenId4VCIConfig = .init(
    client: .public(id: WALLET_DEV_CLIENT_ID),
    authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!,
    authorizeIssuanceConfig: .favorScopes
  )
  
  func testGivenMockDataBatchCredentialIssuance() async throws {
    
    // Given
    guard let offer = await TestsConstants.createMockCredentialOfferValidEncryptionWithBatchLimit() else {
      XCTAssert(false, "Unable to resolve credential offer")
      return
    }
    
    // Given
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
          path: "batch_credential_issuance_success_response_credentials",
          extension: "json"
        )
      ),
      dpopConstructor: dpopConstructor(
        algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported
      )
    )
    
    do {
      let authorizedRequest = try await issuer.authorizeWithAuthorizationCode(
        serverState: TestsConstants.unAuthorizedRequest.state,
        request: TestsConstants.unAuthorizedRequest,
        authorizationCode: try AuthorizationCode(value: "MZqG9bsQ8UALhsGNlY39Yw=="),
        grant: offer.grants!
      )
      
        XCTAssert(true, "Got access token: \(authorizedRequest.accessToken)")
        XCTAssert(true, "Is no proof required")
      
          let msoMdocPayload: IssuanceRequestPayload = .configurationBased(
            credentialConfigurationIdentifier: try .init(value: PID_MsoMdoc_config_id)
          )
          
          let request: SubmittedRequest = try await issuer.requestCredential(
            request: authorizedRequest,
            bindingKeys: [],
            requestPayload: msoMdocPayload,
            responseEncryptionSpecProvider: { _ in
              spec
            })
      
            switch request {
            case .success(let response):
              if let result = response.credentialResponses.first {
                switch result {
                case .deferred:
                  XCTAssert(false, "Unexpected deferred")
                case .issued(_, let credential, _, _):
                  XCTAssert(true, "credential: \(credential)")
                  return
                }
              } else {
                break
              }
            case .failed(let error):
              XCTAssert(false, error.localizedDescription)
              
            case .invalidProof(let errorDescription):
              XCTAssert(false, errorDescription!)
            }
            XCTAssert(false, "Unexpected")
    } catch {
      XCTAssert(false, error.localizedDescription)
    }
  }
}
