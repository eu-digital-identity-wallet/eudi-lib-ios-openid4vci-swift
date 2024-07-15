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
  
  func testGivenMockDataBatchCredentialIssuance() async throws {
    
    // Given
    guard let offer = await TestsConstants.createMockCredentialOfferValidEncryption() else {
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
          path: "batch_issuance_success_response_credential",
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
                    
          let claimSetMsoMdoc = MsoMdocFormat.MsoMdocClaimSet(
            claims: [
              ("org.iso.18013.5.1", "given_name"),
              ("org.iso.18013.5.1", "family_name"),
              ("org.iso.18013.5.1", "birth_date")
            ]
          )
          
          let claimSetSDJWTVC = GenericClaimSet(claims: [
            "given_name",
            "family_name",
            "birth_date",
          ])
          
          let msoMdocPayload: IssuanceRequestPayload = .configurationBased(
            credentialConfigurationIdentifier: try .init(value: PID_MsoMdoc_config_id),
            claimSet: .msoMdoc(claimSetMsoMdoc)
          )
          
          let sdJwtVCPayload: IssuanceRequestPayload = .configurationBased(
            credentialConfigurationIdentifier: try .init(value: PID_SdJwtVC_config_id),
            claimSet: .generic(claimSetSDJWTVC)
          )
          
          
          let result = try await issuer.requestBatch(
            noProofRequest: authorized,
            requestPayload: [
              msoMdocPayload,
              sdJwtVCPayload
            ],
            responseEncryptionSpecProvider: { _ in
              spec
            })
          
          switch result {
          case .success(let request):
            switch request {
            case .success(let response):
              if let result = response.credentialResponses.first {
                switch result {
                case .deferred:
                  XCTAssert(false, "Unexpected deferred")
                case .issued(_, let credential, _):
                  XCTAssert(true, "credential: \(credential)")
                  return
                }
              } else {
                break
              }
            case .failed(let error):
              XCTAssert(false, error.localizedDescription)
              
            case .invalidProof(_, let errorDescription):
              XCTAssert(false, errorDescription!)
            }
            XCTAssert(false, "Unexpected request")
          case .failure(let error):
            XCTAssert(false, error.localizedDescription)
          }
        } catch {
          XCTAssert(false, error.localizedDescription)
        }
        
        return
      }
      
    case .failure(let error):
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(false, "Unable to get access token")
  }
  
  func testBatchCredentialIssuance() async throws {
    
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

    let bindingKey: BindingKey = .jwk(
      algorithm: alg,
      jwk: publicKeyJWK,
      privateKey: privateKey
    )

    let wallet = Wallet(
      actingUser: .init(
        username: "tneal",
        password: "password"
      ),
      bindingKey: bindingKey,
      dPoPConstructor: nil,
      session: Wallet.walletSession
    )

    let url = "\(CREDENTIAL_ISSUER_PUBLIC_URL)/credentialoffer?credential_offer=\(SdJwtVC_CredentialOffer)"
    
      guard let offer = try? await CredentialOfferRequestResolver(
        fetcher: Fetcher(session: wallet.session),
        credentialIssuerMetadataResolver: CredentialIssuerMetadataResolver(
          fetcher: Fetcher(session: wallet.session)
        ),
        authorizationServerMetadataResolver: AuthorizationServerMetadataResolver(
          oidcFetcher: Fetcher(session: wallet.session),
          oauthFetcher: Fetcher(session: wallet.session)
        )
      ).resolve(
        source: try .init(
          urlString: url
        )
      ).get() else {
      XCTAssert(false, "Unable to resolve credential offer")
      return
    }

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
      parPoster: Poster(session: wallet.session),
      tokenPoster: Poster(session: wallet.session),
      requesterPoster: Poster(session: wallet.session),
      deferredRequesterPoster: Poster(session: wallet.session),
      notificationPoster: Poster(session: wallet.session)
    )
    
    let authorized = try await wallet.authorizeRequestWithAuthCodeUseCase(
      issuer: issuer,
      offer: offer
    )
    
    let claimSetMsoMdoc = MsoMdocFormat.MsoMdocClaimSet(
      claims: [
        ("org.iso.18013.5.1", "given_name"),
        ("org.iso.18013.5.1", "family_name")
      ]
    )
    
    let claimSetSDJWTVC = GenericClaimSet(claims: [
      "given_name",
      "family_name"
    ])
    
    let msoMdocPayload: IssuanceRequestPayload = .configurationBased(
      credentialConfigurationIdentifier: try .init(
        value: PID_MsoMdoc_config_id
      ),
      claimSet: .msoMdoc(claimSetMsoMdoc)
    )
    
    let sdJwtVCPayload: IssuanceRequestPayload = .configurationBased(
      credentialConfigurationIdentifier: try .init(
        value: PID_SdJwtVC_config_id
      ),
      claimSet: .generic(claimSetSDJWTVC)
    )
    
    switch authorized {
      
    case .noProofRequired:
      do {
                  
        let result = try await issuer.requestBatch(
          noProofRequest: authorized,
          requestPayload: [
            msoMdocPayload,
            sdJwtVCPayload
          ],
          responseEncryptionSpecProvider: { _ in
            spec
          })
        
        switch result {
        case .success(let request):
          switch request {
          case .success(let response):
            if let result = response.credentialResponses.first {
              switch result {
              case .deferred:
                XCTAssert(false, "Unexpected deferred")
              case .issued(_, let credential, _):
                XCTAssert(true, "credential: \(credential)")
                return
              }
            } else {
              break
            }
          case .failed(let error):
            XCTAssert(false, error.localizedDescription)
            
          case .invalidProof(_, let errorDescription):
            XCTAssert(false, errorDescription!)
          }
          XCTAssert(false, "Unexpected request")
        case .failure(let error):
          XCTAssert(false, error.localizedDescription)
        }
      } catch {
        XCTExpectFailure()
        XCTAssert(false, error.localizedDescription)
      }
    case .proofRequired:
      do {
                  
        let result = try await issuer.requestBatch(
          proofRequest: authorized,
          bindingKey: bindingKey,
          requestPayload: [
            msoMdocPayload,
            sdJwtVCPayload
          ],
          responseEncryptionSpecProvider: { _ in
            spec
          })
        
        switch result {
        case .success(let request):
          switch request {
          case .success(let response):
            if let result = response.credentialResponses.first {
              switch result {
              case .deferred:
                XCTAssert(false, "Unexpected deferred")
              case .issued(_, let credential, _):
                XCTAssert(true, "credential: \(credential)")
                return
              }
            } else {
              break
            }
          case .failed(let error):
            XCTAssert(false, error.localizedDescription)
            
          case .invalidProof(_, let errorDescription):
            XCTAssert(false, errorDescription!)
          }
          XCTAssert(false, "Unexpected request")
        case .failure(let error):
          XCTAssert(false, error.localizedDescription)
        }
      } catch {
        XCTExpectFailure()
        XCTAssert(false, error.localizedDescription)
      }
    }
  }
}
