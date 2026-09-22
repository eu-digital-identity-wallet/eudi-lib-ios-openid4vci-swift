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
import XCTest
import JOSESwift

@testable import OpenID4VCI

final class ProofTypesPolicyTests: XCTestCase {

  // MARK: - Construction

  func testHaipCompliantPolicy() {
    let policy = ProofTypesPolicy.haipCompliant()

    XCTAssertEqual(policy.supportedAlgorithms.count, 1)
    XCTAssertEqual(policy.supportedAlgorithms.first?.name, "ES256")

    // Verify it's a strict policy with both attested proof types
    if case .strict(let strictPolicy) = policy {
      XCTAssertEqual(strictPolicy.supportedProofTypes, [.jwtWithKeyAttestation, .attestation])
    } else {
      XCTFail("Expected .strict policy")
    }
  }

  // MARK: - validateIssuerMetadata: no-proof case

  func testAcceptsMissingProofTypesSupported() {
    let config = makeConfig(proofTypesSupported: nil)

    XCTAssertNoThrow(try ProofTypesPolicy.haipCompliant().validateIssuerMetadata(
      credentialConfiguration: config
    ))
  }

  func testAcceptsEmptyProofTypesSupported() {
    let config = makeConfig(proofTypesSupported: [:])

    XCTAssertNoThrow(try ProofTypesPolicy.haipCompliant().validateIssuerMetadata(
      credentialConfiguration: config
    ))
  }

  // MARK: - validateIssuerMetadata: accept paths

  func testAcceptsJwtAndAttestationBothWithKeyAttestation() {
    let config = makeConfig(proofTypesSupported: [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .requiredNoConstraints
      ),
      "attestation": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .requiredNoConstraints
      )
    ])

    XCTAssertNoThrow(try ProofTypesPolicy.haipCompliant().validateIssuerMetadata(
      credentialConfiguration: config
    ))
  }

  func testAcceptsJwtOnlyWithKeyAttestation() {
    let config = makeConfig(proofTypesSupported: [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .requiredNoConstraints
      )
    ])

    XCTAssertNoThrow(try ProofTypesPolicy.haipCompliant().validateIssuerMetadata(
      credentialConfiguration: config
    ))
  }

  func testAcceptsAttestationOnlyWithKeyAttestation() {
    let config = makeConfig(proofTypesSupported: [
      "attestation": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .requiredNoConstraints
      )
    ])

    XCTAssertNoThrow(try ProofTypesPolicy.haipCompliant().validateIssuerMetadata(
      credentialConfiguration: config
    ))
  }

  func testAcceptsJwtWithKeyAttestationEvenIfAttestationLacksIt() {
    let config = makeConfig(proofTypesSupported: [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .requiredNoConstraints
      ),
      "attestation": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .notRequired
      )
    ])

    XCTAssertNoThrow(try ProofTypesPolicy.haipCompliant().validateIssuerMetadata(
      credentialConfiguration: config
    ))
  }

  // MARK: - validateIssuerMetadata: reject paths (metadata error)

  func testRejectsJwtWithoutKeyAttestation() {
    let config = makeConfig(proofTypesSupported: [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .notRequired
      )
    ])

    expectError(
      .issuerMetadataNoAttestedProofType,
      try ProofTypesPolicy.haipCompliant().validateIssuerMetadata(credentialConfiguration: config)
    )
  }

  func testRejectsAttestationWithoutKeyAttestation() {
    let config = makeConfig(proofTypesSupported: [
      "attestation": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .notRequired
      )
    ])

    expectError(
      .issuerMetadataNoAttestedProofType,
      try ProofTypesPolicy.haipCompliant().validateIssuerMetadata(credentialConfiguration: config)
    )
  }

  func testRejectsBothWithoutKeyAttestation() {
    let config = makeConfig(proofTypesSupported: [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .notRequired
      ),
      "attestation": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .notRequired
      )
    ])

    expectError(
      .issuerMetadataNoAttestedProofType,
      try ProofTypesPolicy.haipCompliant().validateIssuerMetadata(credentialConfiguration: config)
    )
  }

  func testRejectsUnknownProofTypeOnly() {
    let config = makeConfig(proofTypesSupported: [
      "ldp_vc": ProofTypeSupportedMeta(algorithms: ["ES256"])
    ])

    expectError(
      .issuerMetadataNoAttestedProofType,
      try ProofTypesPolicy.haipCompliant().validateIssuerMetadata(credentialConfiguration: config)
    )
  }

  // MARK: - validateIssuerMetadata: wallet policy restrictions

  func testRejectsWhenWalletSupportsNeitherAdvertisedType() {
    let policy = ProofTypesPolicy.strict(StrictProofPolicy(
      supportedAlgorithms: [JWSAlgorithm(.ES256)],
      supportedProofTypes: []
    ))
    let config = makeConfig(proofTypesSupported: [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .requiredNoConstraints
      ),
      "attestation": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .requiredNoConstraints
      )
    ])

    expectError(
      .proofTypeNotSupportedByWalletPolicy,
      try policy.validateIssuerMetadata(credentialConfiguration: config)
    )
  }

  func testRejectsWhenIssuerOnlyJwtButWalletOnlyAttestation() {
    let policy = ProofTypesPolicy.strict(StrictProofPolicy(
      supportedAlgorithms: [JWSAlgorithm(.ES256)],
      supportedProofTypes: [.attestation]
    ))
    let config = makeConfig(proofTypesSupported: [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .requiredNoConstraints
      )
    ])

    expectError(
      .proofTypeNotSupportedByWalletPolicy,
      try policy.validateIssuerMetadata(credentialConfiguration: config)
    )
  }

  func testRejectsWhenIssuerOnlyAttestationButWalletOnlyJwt() {
    let policy = ProofTypesPolicy.strict(StrictProofPolicy(
      supportedAlgorithms: [JWSAlgorithm(.ES256)],
      supportedProofTypes: [.jwtWithKeyAttestation]
    ))
    let config = makeConfig(proofTypesSupported: [
      "attestation": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .requiredNoConstraints
      )
    ])

    expectError(
      .proofTypeNotSupportedByWalletPolicy,
      try policy.validateIssuerMetadata(credentialConfiguration: config)
    )
  }

  func testRejectsAlgorithmMismatch() {
    let config = makeConfig(proofTypesSupported: [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["RS256"],
        keyAttestationRequirement: .requiredNoConstraints
      ),
      "attestation": ProofTypeSupportedMeta(
        algorithms: ["RS256"],
        keyAttestationRequirement: .requiredNoConstraints
      )
    ])

    expectError(
      .noMatchingAlgorithmForProofType,
      try ProofTypesPolicy.haipCompliant().validateIssuerMetadata(credentialConfiguration: config)
    )
  }

  // MARK: - validate(bindingKey:) for strict policy

  func testValidateRejectsNonAttestationCapableBindingKey() {
    let config = makeConfig(proofTypesSupported: [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .requiredNoConstraints
      ),
      "attestation": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .requiredNoConstraints
      )
    ])

    expectError(
      .bindingKeyNotAttestationCapable,
      try ProofTypesPolicy.haipCompliant().validate(
        credentialConfiguration: config,
        bindingKey: .did(identity: "did:example:123")
      )
    )
  }

  // MARK: - acceptAll policy tests

  func testAcceptAllAcceptsPlainJwtIssuer() {
    let policy = ProofTypesPolicy.acceptAll(supportedAlgorithms: [JWSAlgorithm(.ES256)])
    let config = makeConfig(proofTypesSupported: [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .notRequired
      )
    ])

    XCTAssertNoThrow(try policy.validateIssuerMetadata(credentialConfiguration: config))
  }

  func testAcceptAllAcceptsAttestedIssuer() {
    let policy = ProofTypesPolicy.acceptAll(supportedAlgorithms: [JWSAlgorithm(.ES256)])
    let config = makeConfig(proofTypesSupported: [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .requiredNoConstraints
      )
    ])

    XCTAssertNoThrow(try policy.validateIssuerMetadata(credentialConfiguration: config))
  }

  func testAcceptAllRejectsAlgorithmMismatch() {
    let policy = ProofTypesPolicy.acceptAll(supportedAlgorithms: [JWSAlgorithm(.ES256)])
    let config = makeConfig(proofTypesSupported: [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["RS256"],
        keyAttestationRequirement: .notRequired
      )
    ])

    expectError(
      .noMatchingAlgorithmForProofType,
      try policy.validateIssuerMetadata(credentialConfiguration: config)
    )
  }

  func testAcceptAllRejectsPlainJwtBindingKeyWhenIssuerRequiresAttestation() {
    let policy = ProofTypesPolicy.acceptAll(supportedAlgorithms: [JWSAlgorithm(.ES256)])
    let config = makeConfig(proofTypesSupported: [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .requiredNoConstraints
      )
    ])

    expectError(
      .proofTypeKeyAttestationRequired,
      try policy.validate(
        credentialConfiguration: config,
        bindingKey: makePlainJwtBindingKey()
      )
    )
  }

  // MARK: - flexible policy tests

  func testFlexibleWithPlainJwtAllowedAcceptsPlainJwtIssuer() {
    let policy = ProofTypesPolicy.flexible(FlexibleProofPolicy(
      supportedAlgorithms: [JWSAlgorithm(.ES256)],
      supportedAttestedProofTypes: [.jwtWithKeyAttestation, .attestation],
      allowPlainJwtProof: true
    ))
    let config = makeConfig(proofTypesSupported: [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .notRequired
      )
    ])

    XCTAssertNoThrow(try policy.validateIssuerMetadata(credentialConfiguration: config))
  }

  func testFlexibleWithoutPlainJwtRejectsPlainJwtIssuer() {
    let policy = ProofTypesPolicy.flexible(FlexibleProofPolicy(
      supportedAlgorithms: [JWSAlgorithm(.ES256)],
      supportedAttestedProofTypes: [.jwtWithKeyAttestation, .attestation],
      allowPlainJwtProof: false
    ))
    let config = makeConfig(proofTypesSupported: [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .notRequired
      )
    ])

    expectError(
      .issuerMetadataNoAttestedProofType,
      try policy.validateIssuerMetadata(credentialConfiguration: config)
    )
  }

  func testFlexibleWithPlainJwtAllowedAcceptsAttestedIssuer() {
    let policy = ProofTypesPolicy.flexible(FlexibleProofPolicy(
      supportedAlgorithms: [JWSAlgorithm(.ES256)],
      supportedAttestedProofTypes: [.jwtWithKeyAttestation],
      allowPlainJwtProof: true
    ))
    let config = makeConfig(proofTypesSupported: [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .requiredNoConstraints
      )
    ])

    XCTAssertNoThrow(try policy.validateIssuerMetadata(credentialConfiguration: config))
  }

  // MARK: - Helpers

  private func makeConfig(
    proofTypesSupported: [String: ProofTypeSupportedMeta]?
  ) -> CredentialSupported {
    let definition = SdJwtVcFormat.CredentialDefinition(
      type: "VerifiableCredential",
      claims: []
    )
    let config = SdJwtVcFormat.CredentialConfiguration(
      scope: nil,
      vct: "test_vct",
      cryptographicBindingMethodsSupported: [],
      credentialSigningAlgValuesSupported: [],
      proofTypesSupported: proofTypesSupported,
      credentialMetadata: nil,
      credentialDefinition: definition
    )
    return .sdJwtVc(config)
  }

  private func makePlainJwtBindingKey() -> BindingKey {
    // Create a minimal JWK for testing
    let jwk = try! ECPublicKey(
      crv: .P256,
      x: "WbbPfH2vTcXhlbl1tTQBK4kYPZ7WOZJZKbGQPjbcTrQ",
      y: "h3RrNKl0WE0NVU7IwxEJr1rXnP2_mP4mfQF1sXnRNPg"
    )
    return .jwt(
      algorithm: JWSAlgorithm(.ES256),
      jwk: jwk,
      privateKey: .custom(MockAsyncSigner())
    )
  }

  private func expectError(
    _ expected: CredentialIssuanceError,
    _ expression: @autoclosure () throws -> Void,
    file: StaticString = #filePath,
    line: UInt = #line
  ) {
    XCTAssertThrowsError(try expression(), file: file, line: line) { error in
      guard let issuanceError = error as? CredentialIssuanceError else {
        XCTFail("Expected CredentialIssuanceError, got \(error)", file: file, line: line)
        return
      }
      XCTAssertEqual(
        "\(issuanceError)",
        "\(expected)",
        "Expected \(expected), got \(issuanceError)",
        file: file,
        line: line
      )
    }
  }
}

// Mock signer for testing
private struct MockAsyncSigner: AsyncSignerProtocol {
  var publicKey: any JWK {
    return try! ECPublicKey(
      crv: .P256,
      x: "WbbPfH2vTcXhlbl1tTQBK4kYPZ7WOZJZKbGQPjbcTrQ",
      y: "h3RrNKl0WE0NVU7IwxEJr1rXnP2_mP4mfQF1sXnRNPg"
    )
  }

  func signAsync(_ header: Data, _ payload: Data) async throws -> Data {
    return Data()
  }
}
