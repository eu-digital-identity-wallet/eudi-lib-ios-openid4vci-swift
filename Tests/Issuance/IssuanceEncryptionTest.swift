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

class IssuanceEncryptionTest: XCTestCase {
  
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
  
  func testWhenEncryptionAlgorithmNotSupportedByIssuerThenThrowResponseEncryptionAlgorithmNotSupportedByIssuer() async throws {
  
    // Given
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
    
    let spec = IssuanceResponseEncryptionSpec(
      jwk: publicKeyJWK,
      privateKey: privateKey,
      algorithm: .init(name: alg.name),
      encryptionMethod: .init(.A128CBC_HS256)
    )
    
    // When
    guard let (authorizedRequest, issuer) = await (try? initIssuerWithOfferAndAuthorize(issuanceResponseEncryptionSpec: spec)) else {
      XCTAssert(false, "Unable to create tuple")
      return
    }
    
    // Then
    do {
      let payload: IssuanceRequestPayload = .configurationBased(
        credentialConfigurationIdentifier: try .init(
          value: "MobileDrivingLicense_msoMdoc"
        ),
        claimSet: nil
      )
      _ = try await issuer.requestSingle(
        noProofRequest: authorizedRequest,
        requestPayload: payload,
        responseEncryptionSpecProvider: { _ in
          return spec
        }
      )
      
      XCTAssert(false)
    } catch CredentialIssuanceError.responseEncryptionAlgorithmNotSupportedByIssuer {
      XCTAssert(true)
      
    } catch {
      XCTAssert(false, error.localizedDescription)
    }
  }
  
  func testWhenIssuanceRequestEncryptionMethodNotSupportedByIssuerThrowResponseEncryptionMethodNotSupportedByIssuer() async throws {
    
    // Given
    let privateKey = try KeyController.generateRSAPrivateKey()
    let publicKey = try KeyController.generateRSAPublicKey(from: privateKey)

    let alg = JWSAlgorithm.init(name: "PBES2-HS512+A256KW")
    let publicKeyJWK = try RSAPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "alg": alg.name,
        "use": "sig",
        "kid": UUID().uuidString
      ])
    
    let spec = IssuanceResponseEncryptionSpec(
      jwk: publicKeyJWK,
      privateKey: privateKey,
      algorithm: .init(name: alg.name),
      encryptionMethod: .init(.A128GCM)
    )
    
    // When
    guard let (authorizedRequest, issuer) = await (try? initIssuerWithOfferAndAuthorize(issuanceResponseEncryptionSpec: spec)) else {
      XCTAssert(false, "Unable to create tuple")
      return
    }
    
    // Then
    do {
      let payload: IssuanceRequestPayload = .configurationBased(
        credentialConfigurationIdentifier: try .init(
          value: "MobileDrivingLicense_msoMdoc"
        ),
        claimSet: nil
      )
      _ = try await issuer.requestSingle(
        noProofRequest: authorizedRequest,
        requestPayload: payload,
        responseEncryptionSpecProvider: { _ in
          return spec
        }
      )
      
      XCTAssert(false)
    } catch CredentialIssuanceError.responseEncryptionMethodNotSupportedByIssuer {
      XCTAssert(true)
      
    } catch {
      XCTAssert(false, error.localizedDescription)
    }
  }
  
  func testWhenIssuanceRequestEncryptionAlgorithmNotSupportedByIssuerThrowResponseEncryptionMethodNotSupportedByIssuer() async throws {
    
    // Given
    guard let spec = Issuer.createResponseEncryptionSpecFrom(algorithmsSupported: [.init(.RSA_OAEP_256)], encryptionMethodsSupported: [.init(.A128CBC_HS256)]) else {
      XCTAssert(false, "Could not create encryption spec")
      return
    }
    
    // When
    guard let (authorizedRequest, issuer) = await (try? initIssuerWithOfferAndAuthorizeRequesterGenericError(issuanceResponseEncryptionSpec: spec)) else {
      XCTAssert(false, "Unable to create tuple")
      return
    }
    
    // Then
    do {
      let payload: IssuanceRequestPayload = .configurationBased(
        credentialConfigurationIdentifier: try .init(
          value: "MobileDrivingLicense_msoMdoc"
        ),
        claimSet: nil
      )
      _ = try await issuer.requestSingle(
        noProofRequest: authorizedRequest,
        requestPayload: payload,
        responseEncryptionSpecProvider: { _ in
          return spec
        }
      )
      
    } catch CredentialIssuanceError.responseEncryptionAlgorithmNotSupportedByIssuer {
      XCTAssert(true)
      
    } catch {
      print(error.localizedDescription)
      XCTAssert(false, error.localizedDescription)
    }
  }
}

extension IssuanceEncryptionTest {
  
  private func initIssuerWithOfferAndAuthorize(
    issuanceResponseEncryptionSpec: IssuanceResponseEncryptionSpec
  ) async throws -> (AuthorizedRequest, Issuer)? {
    
    guard let offer = await TestsConstants.createMockCredentialOffer() else {
      XCTAssert(false, "Unable to resolve credential offer")
      return nil
    }

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

    guard let parRequested = try? await issuer.pushAuthorizationCodeRequest(credentialOffer: offer).get() else {
      XCTAssert(false, "Unable to create request")
      return nil
    }
    
    guard let unAuthorized = try? await issuer.handleAuthorizationCode(
      parRequested: parRequested,
      authorizationCode: .init(authorizationCode: UUID().uuidString)
    ).get() else {
      XCTAssert(false, "Unable to create request")
      return nil
    }
    
    if case .authorizationCode = unAuthorized {
      guard let authorizedRequest = try? await issuer.requestAccessToken(authorizationCode: unAuthorized).get() else {
        XCTAssert(false, "Could not get authorized request")
        return nil
      }
      return (authorizedRequest, issuer)
      
    } else {
      
      XCTAssert(false, "Did not expect .par")
      return nil
    }
  }
  
  private func initIssuerWithOfferAndAuthorizeRequesterGenericError(
    issuanceResponseEncryptionSpec: IssuanceResponseEncryptionSpec
  ) async throws -> (AuthorizedRequest, Issuer)? {
    
    guard let offer = await TestsConstants.createMockCredentialOffer() else {
      XCTAssert(false, "Unable to resolve credential offer")
      return nil
    }

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
          path: "no_proof_generic_error_response",
          extension: "json"
        )
      )
    )

    guard let parRequested = try? await issuer.pushAuthorizationCodeRequest(credentialOffer: offer).get() else {
      XCTAssert(false, "Unable to create request")
      return nil
    }
    
    guard let unAuthorized = try? await issuer.handleAuthorizationCode(
      parRequested: parRequested,
      authorizationCode: .init(authorizationCode: UUID().uuidString)
    ).get() else {
      XCTAssert(false, "Unable to create request")
      return nil
    }
    
    if case .authorizationCode = unAuthorized {
      guard let authorizedRequest = try? await issuer.requestAccessToken(authorizationCode: unAuthorized).get() else {
        XCTAssert(false, "Could not get authorized request")
        return nil
      }
      return (authorizedRequest, issuer)
      
    } else {
      
      XCTAssert(false, "Did not expect .par")
      return nil
    }
  }
}
