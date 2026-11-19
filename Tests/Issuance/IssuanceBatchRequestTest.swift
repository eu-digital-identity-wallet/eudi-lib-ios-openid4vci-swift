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
    client: attestionClient,
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

  // MARK: - Duplicate Binding Keys Tests (OpenID4VCI §8)

  /// Tests that a batch credential request with duplicate JWT binding keys is rejected.
  /// OpenID4VCI §8 requires distinct cryptographic material for each credential in a batch.
  func testBatchRequestWithDuplicateJwtBindingKeysIsRejected() async throws {
    // Given
    guard let offer = await TestsConstants.createMockCredentialOfferValidEncryptionWithBatchLimit() else {
      XCTFail("Unable to resolve credential offer")
      return
    }

    let privateKey = try KeyController.generateECDHPrivateKey()
    let publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
    let publicKeyJWK = try ECPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "alg": JWSAlgorithm(.ES256).name,
        "use": "sig",
        "kid": UUID().uuidString
      ]
    )

    let responsePrivateKey = try KeyController.generateRSAPrivateKey()
    let responsePublicKey = try KeyController.generateRSAPublicKey(from: responsePrivateKey)
    let responsePublicKeyJWK = try RSAPublicKey(
      publicKey: responsePublicKey,
      additionalParameters: [
        "alg": JWSAlgorithm(.RS256).name,
        "use": "enc",
        "kid": UUID().uuidString
      ]
    )

    let spec = IssuanceResponseEncryptionSpec(
      jwk: responsePublicKeyJWK,
      privateKey: responsePrivateKey,
      algorithm: .init(.RSA_OAEP_256),
      encryptionMethod: .init(.A128CBC_HS256)
    )

    // Use a config that accepts plain JWT binding keys (not just attestation-capable ones)
    let plainJwtConfig = OpenId4VCIConfig(
      client: attestionClient,
      authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!,
      authorizeIssuanceConfig: .favorScopes,
      proofTypesPolicy: .acceptAll(supportedAlgorithms: [.init(.ES256)])
    )

    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: plainJwtConfig,
      parPoster: Poster(session: NetworkingMock(path: "pushed_authorization_request_response", extension: "json")),
      tokenPoster: Poster(session: NetworkingMock(path: "access_token_request_response_no_proof", extension: "json")),
      requesterPoster: Poster(session: NetworkingMock(path: "batch_credential_issuance_success_response_credentials", extension: "json")),
      noncePoster: Poster(session: NetworkingMock(path: "mock_cnonce_endpoint_response", extension: "json")),
      dpopConstructor: dpopConstructor(algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported)
    )

    let authorizedRequest = try await issuer.authorizeWithAuthorizationCode(
      serverState: TestsConstants.unAuthorizedRequest.state,
      request: TestsConstants.unAuthorizedRequest,
      authorizationCode: try AuthorizationCode(value: "MZqG9bsQ8UALhsGNlY39Yw=="),
      grant: offer.grants!
    )

    // Create two binding keys with the SAME public key (duplicate)
    let bindingKey1: BindingKey = .jwt(
      algorithm: .init(.ES256),
      jwk: publicKeyJWK,
      privateKey: .secKey(privateKey)
    )
    let bindingKey2: BindingKey = .jwt(
      algorithm: .init(.ES256),
      jwk: publicKeyJWK,  // Same key as bindingKey1
      privateKey: .secKey(privateKey)
    )

    let payload: IssuanceRequestPayload = .configurationBased(
      credentialConfigurationIdentifier: try .init(value: PID_MsoMdoc_config_id)
    )

    // When/Then: Should throw batchProofsShareBindingKey error
    do {
      _ = try await issuer.requestCredential(
        request: authorizedRequest,
        bindingKeys: [bindingKey1, bindingKey2],
        requestPayload: payload,
        responseEncryptionSpecProvider: { _ in spec }
      )
      XCTFail("Expected batchProofsShareBindingKey error but request succeeded")
    } catch CredentialIssuanceError.batchProofsShareBindingKey {
      XCTAssert(true, "Correctly rejected duplicate binding keys")
    } catch {
      XCTFail("Expected CredentialIssuanceError.batchProofsShareBindingKey, got \(error)")
    }
  }

  /// Tests that a batch credential request with unique JWT binding keys is accepted.
  func testBatchRequestWithUniqueJwtBindingKeysIsAccepted() async throws {
    // Given
    guard let offer = await TestsConstants.createMockCredentialOfferValidEncryptionWithBatchLimit() else {
      XCTFail("Unable to resolve credential offer")
      return
    }

    // Generate two different key pairs
    let privateKey1 = try KeyController.generateECDHPrivateKey()
    let publicKey1 = try KeyController.generateECDHPublicKey(from: privateKey1)
    let publicKeyJWK1 = try ECPublicKey(
      publicKey: publicKey1,
      additionalParameters: [
        "alg": JWSAlgorithm(.ES256).name,
        "use": "sig",
        "kid": UUID().uuidString
      ]
    )

    let privateKey2 = try KeyController.generateECDHPrivateKey()
    let publicKey2 = try KeyController.generateECDHPublicKey(from: privateKey2)
    let publicKeyJWK2 = try ECPublicKey(
      publicKey: publicKey2,
      additionalParameters: [
        "alg": JWSAlgorithm(.ES256).name,
        "use": "sig",
        "kid": UUID().uuidString
      ]
    )

    let responsePrivateKey = try KeyController.generateRSAPrivateKey()
    let responsePublicKey = try KeyController.generateRSAPublicKey(from: responsePrivateKey)
    let responsePublicKeyJWK = try RSAPublicKey(
      publicKey: responsePublicKey,
      additionalParameters: [
        "alg": JWSAlgorithm(.RS256).name,
        "use": "enc",
        "kid": UUID().uuidString
      ]
    )

    let spec = IssuanceResponseEncryptionSpec(
      jwk: responsePublicKeyJWK,
      privateKey: responsePrivateKey,
      algorithm: .init(.RSA_OAEP_256),
      encryptionMethod: .init(.A128CBC_HS256)
    )

    // Use a config that accepts plain JWT binding keys (not just attestation-capable ones)
    let plainJwtConfig = OpenId4VCIConfig(
      client: attestionClient,
      authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!,
      authorizeIssuanceConfig: .favorScopes,
      proofTypesPolicy: .acceptAll(supportedAlgorithms: [.init(.ES256)])
    )

    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: plainJwtConfig,
      parPoster: Poster(session: NetworkingMock(path: "pushed_authorization_request_response", extension: "json")),
      tokenPoster: Poster(session: NetworkingMock(path: "access_token_request_response_no_proof", extension: "json")),
      requesterPoster: Poster(session: NetworkingMock(path: "batch_credential_issuance_success_response_credentials", extension: "json")),
      noncePoster: Poster(session: NetworkingMock(path: "mock_cnonce_endpoint_response", extension: "json")),
      dpopConstructor: dpopConstructor(algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported)
    )

    let authorizedRequest = try await issuer.authorizeWithAuthorizationCode(
      serverState: TestsConstants.unAuthorizedRequest.state,
      request: TestsConstants.unAuthorizedRequest,
      authorizationCode: try AuthorizationCode(value: "MZqG9bsQ8UALhsGNlY39Yw=="),
      grant: offer.grants!
    )

    // Create two binding keys with DIFFERENT public keys
    let bindingKey1: BindingKey = .jwt(
      algorithm: .init(.ES256),
      jwk: publicKeyJWK1,
      privateKey: .secKey(privateKey1)
    )
    let bindingKey2: BindingKey = .jwt(
      algorithm: .init(.ES256),
      jwk: publicKeyJWK2,  // Different key than bindingKey1
      privateKey: .secKey(privateKey2)
    )

    let payload: IssuanceRequestPayload = .configurationBased(
      credentialConfigurationIdentifier: try .init(value: PID_MsoMdoc_config_id)
    )

    // When/Then: Should succeed
    do {
      let request = try await issuer.requestCredential(
        request: authorizedRequest,
        bindingKeys: [bindingKey1, bindingKey2],
        requestPayload: payload,
        responseEncryptionSpecProvider: { _ in spec }
      )

      switch request {
      case .success:
        XCTAssert(true, "Batch request with unique binding keys succeeded")
      case .failed(let error):
        XCTFail("Request failed: \(error.localizedDescription)")
      case .invalidProof(let errorDescription):
        XCTFail("Invalid proof: \(errorDescription ?? "unknown")")
      }
    } catch {
      XCTFail("Unexpected error: \(error)")
    }
  }

  /// Tests that duplicate key validation works correctly with AsyncSignerProtocol (HSM/custom signers).
  /// This verifies that even when using custom signers, the public key JWK is used for comparison.
  func testBatchRequestWithDuplicateAsyncSignerKeysIsRejected() async throws {
    // Given
    guard let offer = await TestsConstants.createMockCredentialOfferValidEncryptionWithBatchLimit() else {
      XCTFail("Unable to resolve credential offer")
      return
    }

    // Create a key pair - simulating what an HSM would provide (public key exportable)
    let privateKey = try KeyController.generateECDHPrivateKey()
    let publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
    let publicKeyJWK = try ECPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "alg": JWSAlgorithm(.ES256).name,
        "use": "sig",
        "kid": UUID().uuidString
      ]
    )

    // Create two AsyncSigner instances with the SAME underlying key (simulating HSM key reuse)
    let asyncSigner1 = TestSigner(privateKey: privateKey, jwk: publicKeyJWK)
    let asyncSigner2 = TestSigner(privateKey: privateKey, jwk: publicKeyJWK)

    let responsePrivateKey = try KeyController.generateRSAPrivateKey()
    let responsePublicKey = try KeyController.generateRSAPublicKey(from: responsePrivateKey)
    let responsePublicKeyJWK = try RSAPublicKey(
      publicKey: responsePublicKey,
      additionalParameters: [
        "alg": JWSAlgorithm(.RS256).name,
        "use": "enc",
        "kid": UUID().uuidString
      ]
    )

    let spec = IssuanceResponseEncryptionSpec(
      jwk: responsePublicKeyJWK,
      privateKey: responsePrivateKey,
      algorithm: .init(.RSA_OAEP_256),
      encryptionMethod: .init(.A128CBC_HS256)
    )

    let plainJwtConfig = OpenId4VCIConfig(
      client: attestionClient,
      authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!,
      authorizeIssuanceConfig: .favorScopes,
      proofTypesPolicy: .acceptAll(supportedAlgorithms: [.init(.ES256)])
    )

    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: plainJwtConfig,
      parPoster: Poster(session: NetworkingMock(path: "pushed_authorization_request_response", extension: "json")),
      tokenPoster: Poster(session: NetworkingMock(path: "access_token_request_response_no_proof", extension: "json")),
      requesterPoster: Poster(session: NetworkingMock(path: "batch_credential_issuance_success_response_credentials", extension: "json")),
      noncePoster: Poster(session: NetworkingMock(path: "mock_cnonce_endpoint_response", extension: "json")),
      dpopConstructor: dpopConstructor(algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported)
    )

    let authorizedRequest = try await issuer.authorizeWithAuthorizationCode(
      serverState: TestsConstants.unAuthorizedRequest.state,
      request: TestsConstants.unAuthorizedRequest,
      authorizationCode: try AuthorizationCode(value: "MZqG9bsQ8UALhsGNlY39Yw=="),
      grant: offer.grants!
    )

    // Create two binding keys using AsyncSignerProtocol with the SAME public key
    let bindingKey1: BindingKey = .jwt(
      algorithm: .init(.ES256),
      jwk: publicKeyJWK,
      privateKey: .custom(asyncSigner1)
    )
    let bindingKey2: BindingKey = .jwt(
      algorithm: .init(.ES256),
      jwk: publicKeyJWK,  // Same JWK - duplicate!
      privateKey: .custom(asyncSigner2)
    )

    let payload: IssuanceRequestPayload = .configurationBased(
      credentialConfigurationIdentifier: try .init(value: PID_MsoMdoc_config_id)
    )

    // When/Then: Should throw batchProofsShareBindingKey error
    do {
      _ = try await issuer.requestCredential(
        request: authorizedRequest,
        bindingKeys: [bindingKey1, bindingKey2],
        requestPayload: payload,
        responseEncryptionSpecProvider: { _ in spec }
      )
      XCTFail("Expected batchProofsShareBindingKey error but request succeeded")
    } catch CredentialIssuanceError.batchProofsShareBindingKey {
      XCTAssert(true, "Correctly rejected duplicate binding keys with AsyncSignerProtocol")
    } catch {
      XCTFail("Expected CredentialIssuanceError.batchProofsShareBindingKey, got \(error)")
    }
  }

  /// Tests that unique keys with AsyncSignerProtocol are accepted.
  func testBatchRequestWithUniqueAsyncSignerKeysIsAccepted() async throws {
    // Given
    guard let offer = await TestsConstants.createMockCredentialOfferValidEncryptionWithBatchLimit() else {
      XCTFail("Unable to resolve credential offer")
      return
    }

    // Create two DIFFERENT key pairs
    let privateKey1 = try KeyController.generateECDHPrivateKey()
    let publicKey1 = try KeyController.generateECDHPublicKey(from: privateKey1)
    let publicKeyJWK1 = try ECPublicKey(
      publicKey: publicKey1,
      additionalParameters: [
        "alg": JWSAlgorithm(.ES256).name,
        "use": "sig",
        "kid": UUID().uuidString
      ]
    )

    let privateKey2 = try KeyController.generateECDHPrivateKey()
    let publicKey2 = try KeyController.generateECDHPublicKey(from: privateKey2)
    let publicKeyJWK2 = try ECPublicKey(
      publicKey: publicKey2,
      additionalParameters: [
        "alg": JWSAlgorithm(.ES256).name,
        "use": "sig",
        "kid": UUID().uuidString
      ]
    )

    let asyncSigner1 = TestSigner(privateKey: privateKey1, jwk: publicKeyJWK1)
    let asyncSigner2 = TestSigner(privateKey: privateKey2, jwk: publicKeyJWK2)

    let responsePrivateKey = try KeyController.generateRSAPrivateKey()
    let responsePublicKey = try KeyController.generateRSAPublicKey(from: responsePrivateKey)
    let responsePublicKeyJWK = try RSAPublicKey(
      publicKey: responsePublicKey,
      additionalParameters: [
        "alg": JWSAlgorithm(.RS256).name,
        "use": "enc",
        "kid": UUID().uuidString
      ]
    )

    let spec = IssuanceResponseEncryptionSpec(
      jwk: responsePublicKeyJWK,
      privateKey: responsePrivateKey,
      algorithm: .init(.RSA_OAEP_256),
      encryptionMethod: .init(.A128CBC_HS256)
    )

    let plainJwtConfig = OpenId4VCIConfig(
      client: attestionClient,
      authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!,
      authorizeIssuanceConfig: .favorScopes,
      proofTypesPolicy: .acceptAll(supportedAlgorithms: [.init(.ES256)])
    )

    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: plainJwtConfig,
      parPoster: Poster(session: NetworkingMock(path: "pushed_authorization_request_response", extension: "json")),
      tokenPoster: Poster(session: NetworkingMock(path: "access_token_request_response_no_proof", extension: "json")),
      requesterPoster: Poster(session: NetworkingMock(path: "batch_credential_issuance_success_response_credentials", extension: "json")),
      noncePoster: Poster(session: NetworkingMock(path: "mock_cnonce_endpoint_response", extension: "json")),
      dpopConstructor: dpopConstructor(algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported)
    )

    let authorizedRequest = try await issuer.authorizeWithAuthorizationCode(
      serverState: TestsConstants.unAuthorizedRequest.state,
      request: TestsConstants.unAuthorizedRequest,
      authorizationCode: try AuthorizationCode(value: "MZqG9bsQ8UALhsGNlY39Yw=="),
      grant: offer.grants!
    )

    // Create two binding keys using AsyncSignerProtocol with DIFFERENT public keys
    let bindingKey1: BindingKey = .jwt(
      algorithm: .init(.ES256),
      jwk: publicKeyJWK1,
      privateKey: .custom(asyncSigner1)
    )
    let bindingKey2: BindingKey = .jwt(
      algorithm: .init(.ES256),
      jwk: publicKeyJWK2,  // Different JWK
      privateKey: .custom(asyncSigner2)
    )

    let payload: IssuanceRequestPayload = .configurationBased(
      credentialConfigurationIdentifier: try .init(value: PID_MsoMdoc_config_id)
    )

    // When/Then: Should succeed
    do {
      let request = try await issuer.requestCredential(
        request: authorizedRequest,
        bindingKeys: [bindingKey1, bindingKey2],
        requestPayload: payload,
        responseEncryptionSpecProvider: { _ in spec }
      )

      switch request {
      case .success:
        XCTAssert(true, "Batch request with unique AsyncSigner keys succeeded")
      case .failed(let error):
        XCTFail("Request failed: \(error.localizedDescription)")
      case .invalidProof(let errorDescription):
        XCTFail("Invalid proof: \(errorDescription ?? "unknown")")
      }
    } catch {
      XCTFail("Unexpected error: \(error)")
    }
  }

  /// Tests that a batch credential request with duplicate key attestation indices is rejected.
  func testBatchRequestWithDuplicateKeyAttestationIndicesIsRejected() async throws {
    // Given
    guard let offer = await TestsConstants.createMockCredentialOfferopenidKeyAttestationRequired() else {
      XCTFail("Unable to resolve credential offer")
      return
    }

    let privateKey = try KeyController.generateECDHPrivateKey()
    let publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
    let publicKeyJWK = try ECPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "alg": JWSAlgorithm(.ES256).name,
        "use": "sig",
        "kid": UUID().uuidString
      ]
    )

    let spec = IssuanceResponseEncryptionSpec(
      jwk: publicKeyJWK,
      privateKey: privateKey,
      algorithm: .init(.ECDH_ES),
      encryptionMethod: .init(.A128GCM)
    )

    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: config,
      parPoster: Poster(session: NetworkingMock(path: "pushed_authorization_request_response", extension: "json")),
      tokenPoster: Poster(session: NetworkingMock(path: "access_token_request_response_no_proof", extension: "json")),
      requesterPoster: Poster(session: NetworkingMock(path: "batch_credential_issuance_success_response_credentials", extension: "json")),
      noncePoster: Poster(session: NetworkingMock(path: "mock_cnonce_endpoint_response", extension: "json")),
      dpopConstructor: dpopConstructor(algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported)
    )

    let authorizedRequest = try await issuer.authorizeWithAuthorizationCode(
      serverState: TestsConstants.unAuthorizedRequest.state,
      request: TestsConstants.unAuthorizedRequest,
      authorizationCode: try AuthorizationCode(value: "MZqG9bsQ8UALhsGNlY39Yw=="),
      grant: offer.grants!
    )

    // Create two binding keys with the SAME key index (duplicate)
    let bindingKey1: BindingKey = .jwtKeyAttestation(
      algorithm: .init(.ES256),
      keyAttestationJWT: { _ in
        try! .init(jws: .init(compactSerialization: TestsConstants.ketAttestationJWT))
      },
      keyIndex: 0,  // Same index
      privateKey: .secKey(privateKey)
    )
    let bindingKey2: BindingKey = .jwtKeyAttestation(
      algorithm: .init(.ES256),
      keyAttestationJWT: { _ in
        try! .init(jws: .init(compactSerialization: TestsConstants.ketAttestationJWT))
      },
      keyIndex: 0,  // Same index as bindingKey1
      privateKey: .secKey(privateKey)
    )

    let payload: IssuanceRequestPayload = .configurationBased(
      credentialConfigurationIdentifier: try .init(value: "eu.europa.ec.eudiw.pid_vc_sd_jwt")
    )

    // When/Then: Should throw batchProofsShareBindingKey error
    do {
      _ = try await issuer.requestCredential(
        request: authorizedRequest,
        bindingKeys: [bindingKey1, bindingKey2],
        requestPayload: payload,
        responseEncryptionSpecProvider: { _ in spec }
      )
      XCTFail("Expected batchProofsShareBindingKey error but request succeeded")
    } catch CredentialIssuanceError.batchProofsShareBindingKey {
      XCTAssert(true, "Correctly rejected duplicate key attestation indices")
    } catch {
      XCTFail("Expected CredentialIssuanceError.batchProofsShareBindingKey, got \(error)")
    }
  }
}
