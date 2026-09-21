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

/// Direct unit tests for the response-encryption invariants enforced by
/// `CredentialSupported.validateAndPrepareEncryption`.
final class ResponseEncryptionInvariantTests: XCTestCase {

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

  private func makeMetadata(
    responseEncryption: CredentialResponseEncryption
  ) throws -> CredentialIssuerMetadata {
    try .init(
      credentialIssuerIdentifier: .init("https://issuer.example.com"),
      authorizationServers: [],
      credentialEndpoint: .init(string: "https://issuer.example.com/credentials"),
      deferredCredentialEndpoint: nil,
      nonceEndpoint: nil,
      notificationEndpoint: nil,
      credentialResponseEncryption: responseEncryption,
      credentialConfigurationsSupported: [:],
      display: nil
    )
  }

  private func makeCredentialSupported() -> CredentialSupported {
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

  private func makeRequestPayload() throws -> IssuanceRequestPayload {
    .configurationBased(
      credentialConfigurationIdentifier: try .init(value: "some-config-id")
    )
  }

  private func makeRSAResponseEncryptionSpec() throws -> IssuanceResponseEncryptionSpec {
    let privateKey = try KeyController.generateRSAPrivateKey()
    let publicKey = try KeyController.generateRSAPublicKey(from: privateKey)
    let publicKeyJWK = try RSAPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "alg": JWEAlgorithm(.RSA_OAEP_256).name,
        "use": "enc",
        "kid": UUID().uuidString
      ]
    )
    return IssuanceResponseEncryptionSpec(
      jwk: publicKeyJWK,
      privateKey: privateKey,
      algorithm: .init(.RSA_OAEP_256),
      encryptionMethod: .init(.A128CBC_HS256)
    )
  }

  // Wallet configures response encryption but not request encryption.
  // Issuer advertises response encryption. Wallet must not be allowed to
  // request an encrypted response while sending its own body in the clear.
  func testResponseEncryptionSpecRequiresRequestEncryptionSpec() throws {
    let responseSpec = try makeRSAResponseEncryptionSpec()
    let metadata = try makeMetadata(
      responseEncryption: .required(
        algorithmsSupported: [.init(.RSA_OAEP_256)],
        encryptionMethodsSupported: [.init(.A128CBC_HS256)],
        compressionMethodsSupported: nil
      )
    )
    let requester = MockIssuanceRequester(issuerMetadata: metadata)

    XCTAssertThrowsError(
      try makeCredentialSupported().toIssuanceRequest(
        requester: requester,
        proofs: [],
        issuancePayload: try makeRequestPayload(),
        requestEncryptionSpec: nil,
        responseEncryptionSpecProvider: { _ in responseSpec }
      )
    ) { error in
      guard case CredentialIssuanceError.responseEncryptionRequiresRequestEncryption = error else {
        XCTFail("Expected responseEncryptionRequiresRequestEncryption, got \(error)")
        return
      }
    }
  }

  // When the issuer's response encryption is .notSupported, the wallet's spec
  // is inert and the invariant should not fire even without a request spec.
  func testWalletConfigInvariantDoesNotFireWhenIssuerHasNoResponseEncryption() throws {
    let responseSpec = try makeRSAResponseEncryptionSpec()
    let metadata = try makeMetadata(responseEncryption: .notSupported)
    let requester = MockIssuanceRequester(issuerMetadata: metadata)

    XCTAssertNoThrow(
      try makeCredentialSupported().toIssuanceRequest(
        requester: requester,
        proofs: [],
        issuancePayload: try makeRequestPayload(),
        requestEncryptionSpec: nil,
        responseEncryptionSpecProvider: { _ in responseSpec }
      )
    )
  }


  // Issuer mandates response encryption; wallet's provider returns nil (for
  // example: no supported algorithm, key generation failed). The request must
  // fail closed rather than proceed unencrypted.
  func testIssuerRequiredResponseEncryptionRejectsNilSpec() throws {
    let metadata = try makeMetadata(
      responseEncryption: .required(
        algorithmsSupported: [.init(.RSA_OAEP_256)],
        encryptionMethodsSupported: [.init(.A128CBC_HS256)],
        compressionMethodsSupported: nil
      )
    )
    let requester = MockIssuanceRequester(issuerMetadata: metadata)

    XCTAssertThrowsError(
      try makeCredentialSupported().toIssuanceRequest(
        requester: requester,
        proofs: [],
        issuancePayload: try makeRequestPayload(),
        requestEncryptionSpec: nil,
        responseEncryptionSpecProvider: { _ in nil }
      )
    ) { error in
      guard case CredentialIssuanceError.responseEncryptionRequiredByIssuerButSpecMissing = error else {
        XCTFail("Expected responseEncryptionRequiredByIssuerButSpecMissing, got \(error)")
        return
      }
    }
  }
}
