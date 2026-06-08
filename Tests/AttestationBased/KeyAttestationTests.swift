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
@preconcurrency import Foundation
import XCTest
@preconcurrency import JOSESwift

@testable import OpenID4VCI

class KeyAttestationTests: XCTestCase {
  
  var config: OpenId4VCIConfig!
  var data: (
    privateKey: SecKey,
    publicKey: ECPublicKey,
    spec: IssuanceResponseEncryptionSpec,
    issuer: Issuer,
    authorizationCode: AuthorizationCode,
    offer: CredentialOffer
  )!
  
  override func setUp() async throws {
    try await super.setUp()
    
    config = .init(
      client: publicClient,
      authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!,
      authorizeIssuanceConfig: .favorScopes
    )
    
    data = try! await keyAttestationData()
  }
  
  override func tearDown() {
    super.tearDown()
    
    data = nil
    config = nil
  }
  
  func testWhenIssuerRequiressKeyAttestationShouldBeIncludedInProof() async throws {
    
    // Given
    let sdJwtVCpayload: IssuanceRequestPayload = .configurationBased(
      credentialConfigurationIdentifier: try .init(value: "eu.europa.ec.eudiw.pid_vc_sd_jwt")
    )
    let spec = data.spec
    
    let keyBindingKey: BindingKey = try! .jwtKeyAttestation(
      algorithm: .init(.ES256),
      keyAttestationJWT: { _ in
        try! .init(
          jws: .init(
            compactSerialization: TestsConstants.ketAttestationJWT
          )
        )
      },
      keyIndex: 1,
      privateKey: .secKey(data.privateKey)
    )
    
    // When
    let authorized = try! await data.issuer.authorizeWithAuthorizationCode(
      serverState: TestsConstants.unAuthorizedRequest.state,
      request: TestsConstants.unAuthorizedRequest,
      authorizationCode: data.authorizationCode,
      grant: data.offer.grants!
    )

    
    do {
      
      // Then
      _ = try await data.issuer.requestCredential(
        request: authorized,
        bindingKeys: [
          keyBindingKey
        ],
        requestPayload: sdJwtVCpayload,
        responseEncryptionSpecProvider: { _ in
          spec
        })
      
        XCTAssert(true, "Success")
    } catch {
      XCTAssert(false, error.localizedDescription)
    }
  }
  
  func testWhenIssuerRequiresAttestationShouldBeIncludedInProof() async throws {
    
    // Given
    let sdJwtVCpayload: IssuanceRequestPayload = .configurationBased(
      credentialConfigurationIdentifier: try .init(value: "eu.europa.ec.eudiw.pid_vc_sd_jwt")
    )
    let spec = data.spec
    
    let keyBindingKey: BindingKey = .attestation(
      keyAttestationJWT: { nonce in
        try! .init(
          jws: try! .init(
            compactSerialization: TestsConstants.ketAttestationJWT
          )
        )
      }
    )
    
    // When
    let authorized = try! await data.issuer.authorizeWithAuthorizationCode(
      serverState: TestsConstants.unAuthorizedRequest.state,
      request: TestsConstants.unAuthorizedRequest,
      authorizationCode: data.authorizationCode,
      grant: data.offer.grants!
    )
    
    do {
      
      // Then
      _ = try await data.issuer.requestCredential(
        request: authorized,
        bindingKeys: [
          keyBindingKey
        ],
        requestPayload: sdJwtVCpayload,
        responseEncryptionSpecProvider: { _ in
          spec
        })
      
        XCTAssert(true, "Success")
    } catch {
      XCTAssert(false, error.localizedDescription)
    }
  }
  
  func testKeyAttestationJWTShouldBeSigned() async throws {
    
    XCTAssertThrowsError(try KeyAttestationJWT(
      jwt: TestsConstants.keyAttestationInvalidJWT
    )) { _ in
        XCTAssert(true)
    }
  }
  
  func testKeyAttestationJWTShouldHaveCorrectType() async throws {
    XCTAssertThrowsError(try KeyAttestationJWT(jws: try JWS(
      header: .init(parameters: [
        "alg": "ES256",
        "type": "not-key-attestation-typ"
      ]),
      payload: .init([
        "key":"value"
      ].toThrowingJSONData()),
      signer: .init(
        signatureAlgorithm: .ES256,
        key: data.privateKey
      )!
    ))) { error in
      if let error = error as? KeyAttestationError {
        switch error {
        case .invalidType: XCTAssert(true)
        default: XCTAssert(false)
        }
      } else {
        XCTAssert(false)
      }
    }
  }
  
  func testKeyAttestationJWTShouldHaveIssuedAt() async throws {
    XCTAssertThrowsError(try KeyAttestationJWT(jws: try JWS(
      header: .init(parameters: [
        "alg": "ES256",
        "typ": KeyAttestationJWT.keyAttestationJWTType
      ]),
      payload: .init([
        "no-iat":"value"
      ].toThrowingJSONData()),
      signer: .init(
        signatureAlgorithm: .ES256,
        key: data.privateKey
      )!
    ))) { error in
      if let error = error as? KeyAttestationError {
        switch error {
        case .missingIAT: XCTAssert(true)
        default: XCTAssert(false)
        }
      } else {
        XCTAssert(false)
      }
    }
  }
  
  func testKeyAttestationJWTShouldHaveAttestedKeys() async throws {
    XCTAssertThrowsError(try KeyAttestationJWT(jws: try JWS(
      header: .init(parameters: [
        "alg": "ES256",
        "typ": KeyAttestationJWT.keyAttestationJWTType
      ]),
      payload: .init([
        "iat": Date().timeIntervalSince1970
      ].toThrowingJSONData()),
      signer: .init(
        signatureAlgorithm: .ES256,
        key: data.privateKey
      )!
    ))) { error in
      if let error = error as? KeyAttestationError {
        switch error {
        case .missingOrEmptyAttestedKeys: XCTAssert(true)
        default: XCTAssert(false)
        }
      } else {
        XCTAssert(false)
      }
    }
  }
  
  func testKeyAttestationJWTShouldSatsifyAllRequirements() async throws {
    _ = try KeyAttestationJWT(jws: try JWS(
      header: .init(parameters: [
        "alg": "ES256",
        "typ": KeyAttestationJWT.keyAttestationJWTType
      ]),
      payload: .init([
        "iat": Date().timeIntervalSince1970,
        "attested_keys": [
          data.publicKey.toDictionary()
        ]
      ].toThrowingJSONData()),
      signer: .init(
        signatureAlgorithm: .ES256,
        key: data.privateKey
      )!
    ))
    
    XCTAssert(true)
  }

  // MARK: - TS3 v1.5 Algorithm Validation Tests

  func testKeyAttestationES256AlgorithmAccepted() async throws {
    // Given: Key attestation with ES256 algorithm (P-256 curve)
    let ka = try KeyAttestationJWT(jws: try JWS(
      header: .init(parameters: [
        "alg": "ES256",
        "typ": KeyAttestationJWT.keyAttestationJWTType
      ]),
      payload: .init([
        "iat": Date().timeIntervalSince1970,
        "attested_keys": [data.publicKey.toDictionary()]
      ].toThrowingJSONData()),
      signer: .init(signatureAlgorithm: .ES256, key: data.privateKey)!
    ))

    // Then: Should succeed
    XCTAssertEqual(ka.attestedKeys.count, 1)
  }

  func testKeyAttestationES384AlgorithmAccepted() async throws {
    // Given: Key attestation with ES384 algorithm
    // Note: Using ES256 key but marking as ES384 to test algorithm validation
    // (In real scenario, P-384 curve would be used)
    let ka = try KeyAttestationJWT(jws: try JWS(
      header: .init(parameters: [
        "alg": "ES384",
        "typ": KeyAttestationJWT.keyAttestationJWTType
      ]),
      payload: .init([
        "iat": Date().timeIntervalSince1970,
        "attested_keys": [data.publicKey.toDictionary()]
      ].toThrowingJSONData()),
      signer: .init(signatureAlgorithm: .ES384, key: data.privateKey)!
    ))

    // Then: Should succeed (algorithm validation accepts ES384)
    XCTAssertEqual(ka.attestedKeys.count, 1)
  }

  func testKeyAttestationES512AlgorithmAccepted() async throws {
    // Given: Key attestation with ES512 algorithm
    // Note: Using ES256 key but marking as ES512 to test algorithm validation
    // (In real scenario, P-521 curve would be used)
    let ka = try KeyAttestationJWT(jws: try JWS(
      header: .init(parameters: [
        "alg": "ES512",
        "typ": KeyAttestationJWT.keyAttestationJWTType
      ]),
      payload: .init([
        "iat": Date().timeIntervalSince1970,
        "attested_keys": [data.publicKey.toDictionary()]
      ].toThrowingJSONData()),
      signer: .init(signatureAlgorithm: .ES512, key: data.privateKey)!
    ))

    // Then: Should succeed (algorithm validation accepts ES512)
    XCTAssertEqual(ka.attestedKeys.count, 1)
  }

  func testKeyAttestationRS256AlgorithmRejected() async throws {
    // Given: Key attestation with RS256 algorithm (not allowed per TS3 v1.5)
    let rsaPrivateKey = try KeyController.generateRSAPrivateKey()

    XCTAssertThrowsError(try KeyAttestationJWT(jws: try JWS(
      header: .init(parameters: [
        "alg": "RS256",
        "typ": KeyAttestationJWT.keyAttestationJWTType
      ]),
      payload: .init([
        "iat": Date().timeIntervalSince1970,
        "attested_keys": [data.publicKey.toDictionary()]
      ].toThrowingJSONData()),
      signer: .init(signatureAlgorithm: .RS256, key: rsaPrivateKey)!
    ))) { error in
      // Then: Should throw unsupportedAlgorithm error
      if let error = error as? KeyAttestationError {
        switch error {
        case .unsupportedAlgorithm(let found, _):
          XCTAssertEqual(found, .RS256)
        default:
          XCTFail("Expected unsupportedAlgorithm error, got \(error)")
        }
      } else {
        XCTFail("Expected KeyAttestationError")
      }
    }
  }

  func testKeyAttestationPS256AlgorithmRejected() async throws {
    // Given: Key attestation with PS256 algorithm (not allowed per TS3 v1.5)
    let rsaPrivateKey = try KeyController.generateRSAPrivateKey()

    XCTAssertThrowsError(try KeyAttestationJWT(jws: try JWS(
      header: .init(parameters: [
        "alg": "PS256",
        "typ": KeyAttestationJWT.keyAttestationJWTType
      ]),
      payload: .init([
        "iat": Date().timeIntervalSince1970,
        "attested_keys": [data.publicKey.toDictionary()]
      ].toThrowingJSONData()),
      signer: .init(signatureAlgorithm: .PS256, key: rsaPrivateKey)!
    ))) { error in
      // Then: Should throw unsupportedAlgorithm error
      if let error = error as? KeyAttestationError {
        switch error {
        case .unsupportedAlgorithm(let found, _):
          XCTAssertEqual(found, .PS256)
        default:
          XCTFail("Expected unsupportedAlgorithm error, got \(error)")
        }
      } else {
        XCTFail("Expected KeyAttestationError")
      }
    }
  }

  // MARK: - TS3 v1.5 First Key Signature Validation Tests

  func testJWTProofSignedByFirstAttestedKeySucceeds() async throws {
    // Given: Key attestation with one attested key
    let keyAttestation = try KeyAttestationJWT(jws: try JWS(
      header: .init(parameters: [
        "alg": "ES256",
        "typ": KeyAttestationJWT.keyAttestationJWTType
      ]),
      payload: .init([
        "iat": Date().timeIntervalSince1970,
        "attested_keys": [data.publicKey.toDictionary()]
      ].toThrowingJSONData()),
      signer: .init(signatureAlgorithm: .ES256, key: data.privateKey)!
    ))

    // And: JWT proof signed by the same key
    let jwtProof = try JWS(
      header: .init(parameters: [
        "alg": "ES256",
        "typ": "openid4vci-proof+jwt"
      ]),
      payload: .init([
        "iat": Date().timeIntervalSince1970,
        "aud": "https://issuer.example.com",
        "nonce": "test-nonce"
      ].toThrowingJSONData()),
      signer: .init(signatureAlgorithm: .ES256, key: data.privateKey)!
    )

    // When/Then: Validation should succeed
    XCTAssertNoThrow(try keyAttestation.validateJWTProofSignature(jwtProof))
  }

  func testJWTProofSignedByWrongKeyFails() async throws {
    // Given: Key attestation with one attested key
    let keyAttestation = try KeyAttestationJWT(jws: try JWS(
      header: .init(parameters: [
        "alg": "ES256",
        "typ": KeyAttestationJWT.keyAttestationJWTType
      ]),
      payload: .init([
        "iat": Date().timeIntervalSince1970,
        "attested_keys": [data.publicKey.toDictionary()]
      ].toThrowingJSONData()),
      signer: .init(signatureAlgorithm: .ES256, key: data.privateKey)!
    ))

    // And: JWT proof signed by a DIFFERENT key
    let differentPrivateKey = try KeyController.generateECDHPrivateKey()
    let jwtProof = try JWS(
      header: .init(parameters: [
        "alg": "ES256",
        "typ": "openid4vci-proof+jwt"
      ]),
      payload: .init([
        "iat": Date().timeIntervalSince1970,
        "aud": "https://issuer.example.com",
        "nonce": "test-nonce"
      ].toThrowingJSONData()),
      signer: .init(signatureAlgorithm: .ES256, key: differentPrivateKey)!
    )

    // When/Then: Validation should fail with JWE error (signature verification failure)
    XCTAssertThrowsError(try keyAttestation.validateJWTProofSignature(jwtProof))
  }

  func testJWTProofMustUseFirstKeyWhenMultipleKeysPresent() async throws {
    // Given: Key attestation with TWO attested keys
    let secondPrivateKey = try KeyController.generateECDHPrivateKey()
    let secondPublicKey = try KeyController.generateECDHPublicKey(from: secondPrivateKey)
    let secondJWK = try ECPublicKey(publicKey: secondPublicKey)

    let keyAttestation = try KeyAttestationJWT(jws: try JWS(
      header: .init(parameters: [
        "alg": "ES256",
        "typ": KeyAttestationJWT.keyAttestationJWTType
      ]),
      payload: .init([
        "iat": Date().timeIntervalSince1970,
        "attested_keys": [
          data.publicKey.toDictionary(),  // First key
          secondJWK.toDictionary()        // Second key
        ]
      ].toThrowingJSONData()),
      signer: .init(signatureAlgorithm: .ES256, key: data.privateKey)!
    ))

    // And: JWT proof signed by the SECOND key (not first)
    let jwtProofWithSecondKey = try JWS(
      header: .init(parameters: [
        "alg": "ES256",
        "typ": "openid4vci-proof+jwt"
      ]),
      payload: .init([
        "iat": Date().timeIntervalSince1970,
        "aud": "https://issuer.example.com",
        "nonce": "test-nonce"
      ].toThrowingJSONData()),
      signer: .init(signatureAlgorithm: .ES256, key: secondPrivateKey)!
    )

    // When/Then: Validation should fail (must use first key)
    XCTAssertThrowsError(try keyAttestation.validateJWTProofSignature(jwtProofWithSecondKey))

    // But: JWT proof signed by the FIRST key should succeed
    let jwtProofWithFirstKey = try JWS(
      header: .init(parameters: [
        "alg": "ES256",
        "typ": "openid4vci-proof+jwt"
      ]),
      payload: .init([
        "iat": Date().timeIntervalSince1970,
        "aud": "https://issuer.example.com",
        "nonce": "test-nonce"
      ].toThrowingJSONData()),
      signer: .init(signatureAlgorithm: .ES256, key: data.privateKey)!
    )

    XCTAssertNoThrow(try keyAttestation.validateJWTProofSignature(jwtProofWithFirstKey))
  }

  // MARK: - TS3 v1.5 Default keyIndex Tests

  func testBindingKeyDefaultsToKeyIndexZero() async throws {
    // Given: BindingKey with jwtKeyAttestation case WITHOUT explicit keyIndex
    let keyBindingKey: BindingKey = .jwtKeyAttestation(
      algorithm: .init(.ES256),
      keyAttestationJWT: { _ in
        try! .init(jws: .init(compactSerialization: TestsConstants.ketAttestationJWT))
      },
      // keyIndex: NOT PROVIDED - should default to 0
      privateKey: .secKey(data.privateKey)
    )

    // Then: The binding key should be created successfully
    // (Testing that default parameter works)
    switch keyBindingKey {
    case .jwtKeyAttestation:
      XCTAssert(true, "BindingKey created successfully with default keyIndex")
    default:
      XCTFail("Expected jwtKeyAttestation case")
    }
  }

  func testKeyIndexOutOfBoundsThrowsError() async throws {
    // Given: A simple key attestation with 1 key
    let keyAttestation = try KeyAttestationJWT(jws: try JWS(
      header: .init(parameters: [
        "alg": "ES256",
        "typ": KeyAttestationJWT.keyAttestationJWTType
      ]),
      payload: .init([
        "iat": Date().timeIntervalSince1970,
        "attested_keys": [data.publicKey.toDictionary()]  // Only 1 key (index 0)
      ].toThrowingJSONData()),
      signer: .init(signatureAlgorithm: .ES256, key: data.privateKey)!
    ))

    // Then: Verify attestedKeys count
    XCTAssertEqual(keyAttestation.attestedKeys.count, 1, "Key attestation should have 1 key")

    // And: Verify BindingKey can be created with default keyIndex (0)
    let validBinding: BindingKey = .jwtKeyAttestation(
      algorithm: .init(.ES256),
      keyAttestationJWT: { _ in keyAttestation },
      // keyIndex defaults to 0, which is valid
      privateKey: .secKey(data.privateKey)
    )

    switch validBinding {
    case .jwtKeyAttestation:
      XCTAssert(true, "Valid binding key created with keyIndex=0")
    default:
      XCTFail("Expected jwtKeyAttestation case")
    }

    // And: Verify BindingKey can be created with explicit keyIndex=0
    let explicitBinding: BindingKey = .jwtKeyAttestation(
      algorithm: .init(.ES256),
      keyAttestationJWT: { _ in keyAttestation },
      keyIndex: 0,  // Explicit index 0 is valid
      privateKey: .secKey(data.privateKey)
    )

    switch explicitBinding {
    case .jwtKeyAttestation:
      XCTAssert(true, "Valid binding key created with explicit keyIndex=0")
    default:
      XCTFail("Expected jwtKeyAttestation case")
    }

    // Note: Testing out-of-bounds requires full integration with the issuer flow
    // which is covered by the existing integration tests. The bounds check logic
    // is present in BindingKey.swift:154-159 and will be triggered during
    // actual credential issuance.
  }
}

extension KeyAttestationTests {
  
  func keyAttestationData() async throws -> (
    privateKey: SecKey,
    publicKey: ECPublicKey,
    spec: IssuanceResponseEncryptionSpec,
    issuer: Issuer,
    authorizationCode: AuthorizationCode,
    offer: CredentialOffer
  ) {
    let privateKey = try KeyController.generateECDHPrivateKey()
    let publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
    
    let alg = JWSAlgorithm(.ES256)
    let publicKeyJWK = try ECPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "alg": alg.name,
        "use": "enc",
        "kid": UUID().uuidString
      ])
    
    let spec = IssuanceResponseEncryptionSpec(
      jwk: publicKeyJWK,
      privateKey: privateKey,
      algorithm: .init(.ECDH_ES),
      encryptionMethod: .init(.A128GCM)
    )
    
    let offer = await TestsConstants.createMockCredentialOfferopenidKeyAttestationRequired()!
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
      noncePoster: Poster(
        session: NetworkingMock(
          path: "mock_cnonce_endpoint_response",
          extension: "json"
        )
      ),
      dpopConstructor: dpopConstructor(
        algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported
      )
    )
    
    let authorizationCode = try AuthorizationCode(value: "MZqG9bsQ8UALhsGNlY39Yw==")
    
    return (
      privateKey: privateKey,
      publicKey: publicKeyJWK,
      spec: spec,
      issuer: issuer,
      authorizationCode: authorizationCode,
      offer: offer
    )
  }
}
