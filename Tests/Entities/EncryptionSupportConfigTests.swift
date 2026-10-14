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

final class EncryptionSupportConfigTests: XCTestCase {

  // MARK: - Defaults

  func testDefaultConfigPreservesPreviousBehaviour() {
    let config = EncryptionSupportConfig.default

    XCTAssertEqual(config.credentialResponseEncryptionPolicy, .supported)
    XCTAssertEqual(config.ecConfig?.ecKeyCurve, .P256)
    XCTAssertEqual(
      config.ecConfig?.supportedJWEAlgorithms.map(\.name),
      ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]
    )
    XCTAssertEqual(config.rsaConfig?.rcaKeySize, 2048)
    XCTAssertEqual(
      config.rsaConfig?.supportedJWEAlgorithms.map(\.name),
      ["RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512"]
    )
    XCTAssertEqual(
      config.supportedEncryptionMethods.map(\.name),
      ["A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"]
    )
    XCTAssertEqual(config.supportedEncryptionAlgorithms.count, 9)
  }

  func testOpenId4VCIConfigDefaultsToDefaultEncryptionSupportConfig() {
    let config = OpenId4VCIConfig(
      client: .public(id: "wallet"),
      authFlowRedirectionURI: URL(string: "wallet://cb")!
    )
    XCTAssertEqual(config.encryptionSupportConfig.credentialResponseEncryptionPolicy, .supported)
    XCTAssertNotNil(config.encryptionSupportConfig.ecConfig)
    XCTAssertNotNil(config.encryptionSupportConfig.rsaConfig)
  }

  // MARK: - Response encryption: algorithm selection

  func testIssuerPreferenceOrderIsPreserved() throws {
    let spec = Issuer.createResponseEncryptionSpec(
      algorithmsSupported: [.init(.RSA_OAEP_256), .init(.ECDH_ES)],
      encryptionMethodsSupported: [.init(.A128GCM)],
      walletConfig: .default
    )
    XCTAssertEqual(spec?.algorithm.name, "RSA-OAEP-256")
    XCTAssertEqual(spec?.jwk?.keyType, .RSA)
  }

  func testDisablingRSASelectsECDHEvenWhenIssuerListsRSAFirst() throws {
    let walletConfig = EncryptionSupportConfig(
      ecConfig: EcConfig(),
      rsaConfig: nil
    )
    let spec = Issuer.createResponseEncryptionSpec(
      algorithmsSupported: [.init(.RSA_OAEP_256), .init(.ECDH_ES_A256KW), .init(.ECDH_ES)],
      encryptionMethodsSupported: [.init(.A256GCM)],
      walletConfig: walletConfig
    )
    XCTAssertEqual(spec?.algorithm.name, "ECDH-ES+A256KW")
    XCTAssertEqual(spec?.encryptionMethod.name, "A256GCM")
    XCTAssertEqual(spec?.jwk?.keyType, .EC)
    XCTAssertEqual(spec?.jwk?["alg"], "ECDH-ES+A256KW")
    XCTAssertEqual(spec?.jwk?["use"], "enc")
  }

  func testDisablingECSelectsRSAEvenWhenIssuerListsECFirst() throws {
    let walletConfig = EncryptionSupportConfig(
      ecConfig: nil,
      rsaConfig: RsaConfig()
    )
    let spec = Issuer.createResponseEncryptionSpec(
      algorithmsSupported: [.init(.ECDH_ES), .init(.RSA_OAEP)],
      encryptionMethodsSupported: [.init(.A128CBC_HS256)],
      walletConfig: walletConfig
    )
    XCTAssertEqual(spec?.algorithm.name, "RSA-OAEP")
    XCTAssertEqual(spec?.jwk?.keyType, .RSA)
  }

  func testRSAAlgorithmAllowListIsHonoured() throws {
    let walletConfig = EncryptionSupportConfig(
      ecConfig: nil,
      rsaConfig: RsaConfig(supportedJWEAlgorithms: [.init(.RSA_OAEP_256)])
    )
    let spec = Issuer.createResponseEncryptionSpec(
      algorithmsSupported: [.init(.RSA_OAEP_384), .init(.RSA_OAEP_512), .init(.RSA_OAEP_256)],
      encryptionMethodsSupported: [.init(.A128GCM)],
      walletConfig: walletConfig
    )
    XCTAssertEqual(spec?.algorithm.name, "RSA-OAEP-256")
  }

  func testWalletAlgorithmAllowListIsHonoured() throws {
    let walletConfig = EncryptionSupportConfig(
      ecConfig: EcConfig(supportedJWEAlgorithms: [.init(.ECDH_ES)]),
      rsaConfig: nil
    )
    let spec = Issuer.createResponseEncryptionSpec(
      algorithmsSupported: [.init(.ECDH_ES_A128KW), .init(.ECDH_ES)],
      encryptionMethodsSupported: [.init(.A128GCM)],
      walletConfig: walletConfig
    )
    XCTAssertEqual(spec?.algorithm.name, "ECDH-ES")
  }

  func testNoMutuallySupportedAlgorithmYieldsNil() throws {
    let walletConfig = EncryptionSupportConfig(ecConfig: EcConfig(), rsaConfig: nil)
    let spec = Issuer.createResponseEncryptionSpec(
      algorithmsSupported: [.init(.RSA_OAEP_256)],
      encryptionMethodsSupported: [.init(.A128GCM)],
      walletConfig: walletConfig
    )
    XCTAssertNil(spec)
  }

  func testBothKeyFamiliesDisabledYieldsNil() throws {
    let walletConfig = EncryptionSupportConfig(ecConfig: nil, rsaConfig: nil)
    let spec = Issuer.createResponseEncryptionSpec(
      algorithmsSupported: [.init(.ECDH_ES), .init(.RSA_OAEP_256)],
      encryptionMethodsSupported: [.init(.A128GCM)],
      walletConfig: walletConfig
    )
    XCTAssertNil(spec)
  }

  // MARK: - Response encryption: method selection

  func testFirstIssuerMethodSupportedByWalletIsSelected() throws {
    let walletConfig = EncryptionSupportConfig(
      supportedEncryptionMethods: [.init(.A128GCM), .init(.A128CBC_HS256)]
    )
    let spec = Issuer.createResponseEncryptionSpec(
      algorithmsSupported: [.init(.ECDH_ES)],
      encryptionMethodsSupported: [.init(.A256GCM), .init(.A128CBC_HS256), .init(.A128GCM)],
      walletConfig: walletConfig
    )
    XCTAssertEqual(spec?.encryptionMethod.name, "A128CBC-HS256")
  }

  func testNoMutuallySupportedMethodYieldsNil() throws {
    let walletConfig = EncryptionSupportConfig(
      supportedEncryptionMethods: [.init(.A128GCM)]
    )
    let spec = Issuer.createResponseEncryptionSpec(
      algorithmsSupported: [.init(.ECDH_ES)],
      encryptionMethodsSupported: [.init(.A256GCM)],
      walletConfig: walletConfig
    )
    XCTAssertNil(spec)
  }

  // MARK: - Response encryption: metadata-driven entry point

  func testIssuerWithoutResponseEncryptionYieldsNil() {
    XCTAssertNil(Issuer.createResponseEncryptionSpec(.notSupported, walletConfig: .default))
  }

  func testLegacyEntryPointKeepsFallbackForIssuerWithoutResponseEncryption() {
    let spec = Issuer.createResponseEncryptionSpec(.notSupported)
    XCTAssertEqual(spec?.algorithm.name, "ECDH-ES")
    XCTAssertEqual(spec?.encryptionMethod.name, "A128GCM")
  }

  func testRequiredAndNotRequiredMetadataAreNegotiatedAlike() {
    let walletConfig = EncryptionSupportConfig(ecConfig: EcConfig(), rsaConfig: nil)
    let required = Issuer.createResponseEncryptionSpec(
      .required(
        algorithmsSupported: [.init(.RSA_OAEP_256), .init(.ECDH_ES)],
        encryptionMethodsSupported: [.init(.A128GCM)],
        compressionMethodsSupported: nil
      ),
      walletConfig: walletConfig
    )
    let notRequired = Issuer.createResponseEncryptionSpec(
      .notRequired(
        algorithmsSupported: [.init(.RSA_OAEP_256), .init(.ECDH_ES)],
        encryptionMethodsSupported: [.init(.A128GCM)],
        compressionMethodsSupported: nil
      ),
      walletConfig: walletConfig
    )
    XCTAssertEqual(required?.algorithm.name, "ECDH-ES")
    XCTAssertEqual(notRequired?.algorithm.name, "ECDH-ES")
  }

  func testLegacyEntryPointsUseDefaultConfig() {
    let spec = Issuer.createResponseEncryptionSpecFrom(
      algorithmsSupported: [.init(.A128KW), .init(.ECDH_ES)],
      encryptionMethodsSupported: [.init(.A128GCM)]
    )
    XCTAssertEqual(spec?.algorithm.name, "ECDH-ES")
  }

  // MARK: - Key material

  func testConfiguredCurveIsUsedForECKeyPair() throws {
    let walletConfig = EncryptionSupportConfig(
      ecConfig: EcConfig(ecKeyCurve: .P384),
      rsaConfig: nil
    )
    let spec = try XCTUnwrap(
      Issuer.createResponseEncryptionSpec(
        algorithmsSupported: [.init(.ECDH_ES)],
        encryptionMethodsSupported: [.init(.A128GCM)],
        walletConfig: walletConfig
      )
    )
    XCTAssertEqual(rcaKeySize(of: try XCTUnwrap(spec.privateKey)), 384)
    XCTAssertEqual((spec.jwk as? ECPublicKey)?.crv, .P384)
  }

  func testConfiguredRSAKeySizeIsUsed() throws {
    let walletConfig = EncryptionSupportConfig(
      ecConfig: nil,
      rsaConfig: RsaConfig(rcaKeySize: 3072)
    )
    let spec = try XCTUnwrap(
      Issuer.createResponseEncryptionSpec(
        algorithmsSupported: [.init(.RSA_OAEP_256)],
        encryptionMethodsSupported: [.init(.A128GCM)],
        walletConfig: walletConfig
      )
    )
    XCTAssertEqual(rcaKeySize(of: try XCTUnwrap(spec.privateKey)), 3072)
  }

  func testPrivateKeyDataRebuildsTheSameECKey() throws {
    let walletConfig = EncryptionSupportConfig(
      ecConfig: EcConfig(ecKeyCurve: .P256),
      rsaConfig: nil
    )
    let algorithms: [JWEAlgorithm] = [.init(.ECDH_ES)]
    let methods: [JOSEEncryptionMethod] = [.init(.A128GCM)]

    let original = try XCTUnwrap(
      Issuer.createResponseEncryptionSpec(
        algorithmsSupported: algorithms,
        encryptionMethodsSupported: methods,
        walletConfig: walletConfig
      )
    )
    var error: Unmanaged<CFError>?
    let keyData = try XCTUnwrap(
      SecKeyCopyExternalRepresentation(try XCTUnwrap(original.privateKey), &error) as Data?
    )

    let rebuilt = try XCTUnwrap(
      Issuer.createResponseEncryptionSpec(
        algorithmsSupported: algorithms,
        encryptionMethodsSupported: methods,
        walletConfig: walletConfig,
        privateKeyData: keyData
      )
    )

    let originalJWK = try XCTUnwrap(original.jwk as? ECPublicKey)
    let rebuiltJWK = try XCTUnwrap(rebuilt.jwk as? ECPublicKey)
    XCTAssertEqual(originalJWK.x, rebuiltJWK.x)
    XCTAssertEqual(originalJWK.y, rebuiltJWK.y)
  }

  // MARK: - Wallet policy enforcement

  func testRequiredPolicyRejectsIssuerWithoutResponseEncryption() throws {
    let requester = MockIssuanceRequester(issuerMetadata: try makeMetadata(responseEncryption: .notSupported))

    XCTAssertThrowsError(
      try makeCredentialSupported().toIssuanceRequest(
        requester: requester,
        issuancePayload: try makeRequestPayload(),
        requestEncryptionSpec: nil,
        walletResponseEncryptionPolicy: .required,
        responseEncryptionSpecProvider: { _ in nil }
      )
    ) { error in
      guard case CredentialIssuanceError.responseEncryptionRequiredByWalletButNotSupportedByIssuer = error else {
        XCTFail("Expected responseEncryptionRequiredByWalletButNotSupportedByIssuer, got \(error)")
        return
      }
    }
  }

  func testRequiredPolicyRejectsMissingSpecWhenIssuerDoesNotRequireEncryption() throws {
    let requester = MockIssuanceRequester(
      issuerMetadata: try makeMetadata(
        responseEncryption: .notRequired(
          algorithmsSupported: [.init(.RSA_OAEP_256)],
          encryptionMethodsSupported: [.init(.A128GCM)],
          compressionMethodsSupported: nil
        )
      )
    )

    XCTAssertThrowsError(
      try makeCredentialSupported().toIssuanceRequest(
        requester: requester,
        issuancePayload: try makeRequestPayload(),
        requestEncryptionSpec: nil,
        walletResponseEncryptionPolicy: .required,
        responseEncryptionSpecProvider: { _ in nil }
      )
    ) { error in
      guard case CredentialIssuanceError.responseEncryptionRequiredByWalletButSpecMissing = error else {
        XCTFail("Expected responseEncryptionRequiredByWalletButSpecMissing, got \(error)")
        return
      }
    }
  }

  func testSupportedPolicyAcceptsMissingSpecWhenIssuerDoesNotRequireEncryption() throws {
    let requester = MockIssuanceRequester(
      issuerMetadata: try makeMetadata(
        responseEncryption: .notRequired(
          algorithmsSupported: [.init(.RSA_OAEP_256)],
          encryptionMethodsSupported: [.init(.A128GCM)],
          compressionMethodsSupported: nil
        )
      )
    )

    XCTAssertNoThrow(
      try makeCredentialSupported().toIssuanceRequest(
        requester: requester,
        issuancePayload: try makeRequestPayload(),
        requestEncryptionSpec: nil,
        walletResponseEncryptionPolicy: .supported,
        responseEncryptionSpecProvider: { _ in nil }
      )
    )
  }

  // MARK: - Request encryption

  func testRequestEncryptionSkipsIssuerKeysOfDisabledFamilies() throws {
    let rsaKey = try KeyController.generateRSAPrivateKey()
    let rsaJWK = try RSAPublicKey(publicKey: try KeyController.generateRSAPublicKey(from: rsaKey))
    let ecKey = try KeyController.generateECDHPrivateKey()
    let ecJWK = try ECPublicKey(publicKey: try KeyController.generateECDHPublicKey(from: ecKey))

    let metadata: CredentialRequestEncryption = .notRequired(
      jwks: [rsaJWK, ecJWK],
      encryptionMethodsSupported: [.init(.A128GCM)],
      compressionMethodsSupported: nil
    )

    let withDefault = try Issuer.createRequestEncryptionSpec(metadata, walletConfig: .default)
    XCTAssertEqual(withDefault?.algorithm.name, "RSA-OAEP-256")

    let withoutRSA = try Issuer.createRequestEncryptionSpec(
      metadata,
      walletConfig: EncryptionSupportConfig(ecConfig: EcConfig(), rsaConfig: nil)
    )
    XCTAssertEqual(withoutRSA?.algorithm.name, "ECDH-ES")
    XCTAssertEqual(withoutRSA?.recipientKey.keyType, .EC)

    let nothingUsable = try Issuer.createRequestEncryptionSpec(
      metadata,
      walletConfig: EncryptionSupportConfig(ecConfig: nil, rsaConfig: nil)
    )
    XCTAssertNil(nothingUsable)
  }

  func testRequestEncryptionMethodIsFilteredByWallet() throws {
    let ecKey = try KeyController.generateECDHPrivateKey()
    let ecJWK = try ECPublicKey(publicKey: try KeyController.generateECDHPublicKey(from: ecKey))
    let metadata: CredentialRequestEncryption = .required(
      jwks: [ecJWK],
      encryptionMethodsSupported: [.init(.A256GCM), .init(.A128GCM)],
      compressionMethodsSupported: nil
    )

    let spec = try Issuer.createRequestEncryptionSpec(
      metadata,
      walletConfig: EncryptionSupportConfig(supportedEncryptionMethods: [.init(.A128GCM)])
    )
    XCTAssertEqual(spec?.encryptionMethod.name, "A128GCM")

    let none = try Issuer.createRequestEncryptionSpec(
      metadata,
      walletConfig: EncryptionSupportConfig(supportedEncryptionMethods: [.init(.A128CBC_HS256)])
    )
    XCTAssertNil(none)
  }

  func testRequestEncryptionIsNilWhenIssuerDoesNotSupportIt() throws {
    XCTAssertNil(try Issuer.createRequestEncryptionSpec(.notSupported, walletConfig: .default))
    XCTAssertNil(try Issuer.createRequestEncryptionSpec(nil, walletConfig: .default))
  }

  // MARK: - Helpers

  private func rcaKeySize(of key: SecKey) -> Int? {
    (SecKeyCopyAttributes(key) as? [String: Any])?[kSecAttrKeySizeInBits as String] as? Int
  }

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
}
