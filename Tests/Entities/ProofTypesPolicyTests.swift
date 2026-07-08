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
    XCTAssertEqual(policy.supportedProofTypes, [.jwtWithKeyAttestation, .attestation])
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

  // MARK: - validateIssuerMetadata: reject paths (metadata error)

  func testRejectsJwtOnly() {
    let config = makeConfig(proofTypesSupported: [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .requiredNoConstraints
      )
    ])

    expectError(
      .issuerMetadataNoAttestedProofType,
      try ProofTypesPolicy.haipCompliant().validateIssuerMetadata(credentialConfiguration: config)
    )
  }

  func testRejectsAttestationOnly() {
    let config = makeConfig(proofTypesSupported: [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .requiredNoConstraints
      )
    ])

    expectError(
      .issuerMetadataNoAttestedProofType,
      try ProofTypesPolicy.haipCompliant().validateIssuerMetadata(credentialConfiguration: config)
    )
  }

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
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .requiredNoConstraints
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
    let policy = ProofTypesPolicy(
      supportedAlgorithms: [JWSAlgorithm(.ES256)],
      supportedProofTypes: []
    )
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

  // MARK: - validate(bindingKey:)

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
