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
@preconcurrency import JOSESwift

@testable import OpenID4VCI

/// Verifies that BindingKey.toSupportedProof honors the omitIss flag for both the
/// plain-jwt and jwt-with-key-attestation proof types (finding PAR_VCI_SWIFT_21 / #343).
final class BindingKeyOmitIssTests: XCTestCase {

  // MARK: - Mock requester

  private struct MockIssuanceRequester: IssuanceRequesterType {
    let issuerMetadata: CredentialIssuerMetadata

    func placeIssuanceRequest(
      accessToken: IssuanceAccessToken,
      request: SingleCredential,
      dPopNonce: Nonce?,
      maxRetries: Int,
      encryptionSpec: EncryptionSpec?
    ) async throws -> CredentialIssuanceResponse {
      fatalError("Not used in these tests")
    }

    func placeDeferredCredentialRequest(
      accessToken: IssuanceAccessToken,
      transactionId: TransactionId,
      dPopNonce: Nonce?,
      maxRetries: Int,
      issuanceResponseEncryptionSpec: IssuanceResponseEncryptionSpec?,
      encryptionSpec: EncryptionSpec?
    ) async throws -> DeferredCredentialIssuanceResponse {
      fatalError("Not used in these tests")
    }

    func notifyIssuer(
      accessToken: IssuanceAccessToken?,
      notification: NotificationObject,
      dPopNonce: Nonce?,
      maxRetries: Int
    ) async throws {
      fatalError("Not used in these tests")
    }
  }

  // MARK: - Helpers

  private func metadata() throws -> CredentialIssuerMetadata {
    CredentialIssuerMetadata(
      credentialIssuerIdentifier: try .init("https://issuer.example.com"),
      authorizationServers: [],
      credentialEndpoint: try .init(string: "https://issuer.example.com/credentials"),
      deferredCredentialEndpoint: nil,
      nonceEndpoint: nil,
      notificationEndpoint: nil,
      credentialConfigurationsSupported: [:],
      display: nil
    )
  }

  private func msoMdocCredentialSpec() -> CredentialSupported {
    .msoMdoc(
      MsoMdocFormat.CredentialConfiguration(
        format: MsoMdocFormat.FORMAT,
        scope: nil,
        cryptographicBindingMethodsSupported: [],
        credentialSigningAlgValuesSupported: [],
        proofTypesSupported: nil,
        credentialMetadata: nil,
        docType: "org.example.doc",
        policy: nil,
        credentialReusePolicy: nil
      )
    )
  }

  private func ecKeyPair() throws -> (jwk: ECPublicKey, privateKey: SigningKeyProxy) {
    let privateKey = try KeyController.generateECDHPrivateKey()
    let publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
    let jwk = try ECPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "alg": JWSAlgorithm(.ES256).name,
        "use": "sig",
        "kid": UUID().uuidString
      ]
    )
    return (jwk, .secKey(privateKey))
  }

  private func decodeProofPayload(_ proof: Proof) throws -> [String: Any] {
    guard case .jwt(let compact) = proof else {
      throw ValidationError.error(reason: "Expected .jwt proof")
    }
    let jws = try JWS(compactSerialization: compact)
    let json = try JSONSerialization.jsonObject(with: jws.payload.data())
    guard let dictionary = json as? [String: Any] else {
      throw ValidationError.error(reason: "Payload is not a JSON object")
    }
    return dictionary
  }

  // MARK: - .jwt case

  func testJwtProofDropsIssWhenOmitIssTrue() async throws {
    let (jwk, privateKey) = try ecKeyPair()
    let requester = MockIssuanceRequester(issuerMetadata: try metadata())
    let binding: BindingKey = .jwt(
      algorithm: .init(.ES256),
      jwk: jwk,
      privateKey: privateKey,
      issuer: "wallet-client-id"
    )

    let proof = try await binding.toSupportedProof(
      issuanceRequester: requester,
      credentialSpec: msoMdocCredentialSpec(),
      cNonce: "nonce-123",
      omitIss: true
    )

    let payload = try decodeProofPayload(proof)
    XCTAssertNil(payload[JWTClaimNames.issuer], "iss claim must not appear when omitIss=true")
    XCTAssertEqual(payload[JWTClaimNames.nonce] as? String, "nonce-123")
  }

  func testJwtProofKeepsIssWhenOmitIssFalse() async throws {
    let (jwk, privateKey) = try ecKeyPair()
    let requester = MockIssuanceRequester(issuerMetadata: try metadata())
    let binding: BindingKey = .jwt(
      algorithm: .init(.ES256),
      jwk: jwk,
      privateKey: privateKey,
      issuer: "wallet-client-id"
    )

    let proof = try await binding.toSupportedProof(
      issuanceRequester: requester,
      credentialSpec: msoMdocCredentialSpec(),
      cNonce: "nonce-123",
      omitIss: false
    )

    let payload = try decodeProofPayload(proof)
    XCTAssertEqual(payload[JWTClaimNames.issuer] as? String, "wallet-client-id")
  }

  // MARK: - .jwtKeyAttestation case

  func testJwtKeyAttestationProofDropsIssWhenOmitIssTrue() async throws {
    let (_, privateKey) = try ecKeyPair()
    let requester = MockIssuanceRequester(issuerMetadata: try metadata())
    let keyAttestation = try KeyAttestationJWT(
      jws: try .init(compactSerialization: TestsConstants.ketAttestationJWT)
    )
    let binding: BindingKey = .jwtKeyAttestation(
      algorithm: .init(.ES256),
      keyAttestationJWT: { _ in keyAttestation },
      keyIndex: 0,
      privateKey: privateKey,
      issuer: "wallet-client-id"
    )

    let proof = try await binding.toSupportedProof(
      issuanceRequester: requester,
      credentialSpec: msoMdocCredentialSpec(),
      keyAttestationJwt: keyAttestation,
      cNonce: "nonce-123",
      omitIss: true
    )

    let payload = try decodeProofPayload(proof)
    XCTAssertNil(payload[JWTClaimNames.issuer], "iss claim must not appear when omitIss=true")
  }

  func testJwtKeyAttestationProofKeepsIssWhenOmitIssFalse() async throws {
    let (_, privateKey) = try ecKeyPair()
    let requester = MockIssuanceRequester(issuerMetadata: try metadata())
    let keyAttestation = try KeyAttestationJWT(
      jws: try .init(compactSerialization: TestsConstants.ketAttestationJWT)
    )
    let binding: BindingKey = .jwtKeyAttestation(
      algorithm: .init(.ES256),
      keyAttestationJWT: { _ in keyAttestation },
      keyIndex: 0,
      privateKey: privateKey,
      issuer: "wallet-client-id"
    )

    let proof = try await binding.toSupportedProof(
      issuanceRequester: requester,
      credentialSpec: msoMdocCredentialSpec(),
      keyAttestationJwt: keyAttestation,
      cNonce: "nonce-123",
      omitIss: false
    )

    let payload = try decodeProofPayload(proof)
    XCTAssertEqual(payload[JWTClaimNames.issuer] as? String, "wallet-client-id")
  }
}
