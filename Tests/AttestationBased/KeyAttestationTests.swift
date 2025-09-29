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
    issuanceAuthorization: IssuanceAuthorization,
    offer: CredentialOffer
  )!
  
  override func setUp() async throws {
    try await super.setUp()
    
    config = .init(
      client: .public(id: WALLET_DEV_CLIENT_ID),
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
    
    let keyBindingKey: BindingKey = try! .keyAttestation(
      algorithm: .init(.ES256),
      keyAttestationJWT: {_, _, _ in
        try! .init(
          jws: .init(
            compactSerialization: TestsConstants.ketAttestationJWT
          )
        )
      },
      keyIndex: 1,
      privateKey: .secKey(data.privateKey),
      publicJWK: data.publicKey
    )
    
    // When
    let authorized = try! await data.issuer.authorizeWithAuthorizationCode(
      request: try await data.issuer.handleAuthorizationCode(
        request: TestsConstants.unAuthorizedRequest,
        authorizationCode: data.issuanceAuthorization
      ).get()
    ).get()

    
    do {
      
      // Then
      let result = try await data.issuer.requestCredential(
        request: authorized,
        bindingKeys: [
          keyBindingKey
        ],
        requestPayload: sdJwtVCpayload,
        encryptionSpec: nil,
        responseEncryptionSpecProvider: { _ in
          spec
        })
      
      switch result {
      case .success:
        XCTAssert(true, "Success")
      case .failure(let error):
        XCTAssert(false, error.localizedDescription)
      }
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
    
    let keyBindingKey: BindingKey = try! .attestation(
      keyAttestationJWT: .init(
        jws: .init(
          compactSerialization: TestsConstants.ketAttestationJWT
        )
      )
    )
    
    // When
    let authorized = try! await data.issuer.authorizeWithAuthorizationCode(
      request: try await data.issuer.handleAuthorizationCode(
        request: TestsConstants.unAuthorizedRequest,
        authorizationCode: data.issuanceAuthorization
      ).get()
    ).get()

    
    do {
      
      // Then
      let result = try await data.issuer.requestCredential(
        request: authorized,
        bindingKeys: [
          keyBindingKey
        ],
        requestPayload: sdJwtVCpayload,
        encryptionSpec: nil,
        responseEncryptionSpecProvider: { _ in
          spec
        })
      
      switch result {
      case .success:
        XCTAssert(true, "Success")
      case .failure(let error):
        XCTAssert(false, error.localizedDescription)
      }
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
        "typ": "keyattestation+jwt"
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
        "typ": "keyattestation+jwt"
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
        "typ": "keyattestation+jwt"
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
}

extension KeyAttestationTests {
  
  func keyAttestationData() async throws -> (
    privateKey: SecKey,
    publicKey: ECPublicKey,
    spec: IssuanceResponseEncryptionSpec,
    issuer: Issuer,
    issuanceAuthorization: IssuanceAuthorization,
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
    
    let issuanceAuthorization: IssuanceAuthorization = .authorizationCode(authorizationCode: "MZqG9bsQ8UALhsGNlY39Yw==")
    
    return (
      privateKey: privateKey,
      publicKey: publicKeyJWK,
      spec: spec,
      issuer: issuer,
      issuanceAuthorization: issuanceAuthorization,
      offer: offer
    )
  }
}
