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

  // MARK: - Policy Creation Tests

  func testAcceptAllPolicy() throws {
    let policy = ProofTypesPolicy.acceptAll

    // Create a test credential configuration that requires JWT without key attestation
    let proofTypesSupported: [String: ProofTypeSupportedMeta] = [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .notRequired
      )
    ]
    let credentialConfig = createTestCredentialConfiguration(proofTypesSupported: proofTypesSupported)

    // Create a plain JWT binding key
    let bindingKey = try createJwtBindingKey()

    // Should not throw with acceptAll policy
    XCTAssertNoThrow(try policy.validate(
      credentialConfiguration: credentialConfig,
      bindingKey: bindingKey
    ))
  }

  func testHaipCompliantPolicy() throws {
    let policy = DeviceBoundProofPolicy.haipCompliant()

    XCTAssertEqual(policy.supportedAlgorithms.count, 1)
    XCTAssertEqual(policy.supportedAlgorithms.first?.name, "ES256")
    XCTAssertTrue(policy.supportedProofTypes.contains(.jwtWithKeyAttestation))
    XCTAssertTrue(policy.supportedProofTypes.contains(.attestation))
    XCTAssertFalse(policy.supportedProofTypes.contains(.jwtWithoutKeyAttestation))
  }

  func testDeviceBoundPolicyCreation() throws {
    let policy = DeviceBoundProofPolicy(
      supportedAlgorithms: [JWSAlgorithm(.ES256), JWSAlgorithm(.ES384)],
      supportedProofTypes: [.jwtWithKeyAttestation, .attestation]
    )

    XCTAssertEqual(policy.supportedAlgorithms.count, 2)
    XCTAssertTrue(policy.supportedAlgorithms.contains(where: { $0.name == "ES256" }))
    XCTAssertTrue(policy.supportedAlgorithms.contains(where: { $0.name == "ES384" }))
    XCTAssertEqual(policy.supportedProofTypes.count, 2)
  }

  // MARK: - Validation Tests - JWT Without Key Attestation

  func testDeviceBoundPolicy_RejectsJwtWithoutKeyAttestation() throws {
    let deviceBoundPolicy = DeviceBoundProofPolicy(
      supportedAlgorithms: [JWSAlgorithm(.ES256)],
      supportedProofTypes: [.jwtWithKeyAttestation, .attestation]
    )
    let policy = ProofTypesPolicy.deviceBound(deviceBoundPolicy)

    // Credential requires JWT without key attestation
    let proofTypesSupported: [String: ProofTypeSupportedMeta] = [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .notRequired
      )
    ]
    let credentialConfig = createTestCredentialConfiguration(proofTypesSupported: proofTypesSupported)
    let bindingKey = try createJwtBindingKey()

    // Should throw because policy doesn't support JWT without key attestation
    XCTAssertThrowsError(try policy.validate(
      credentialConfiguration: credentialConfig,
      bindingKey: bindingKey
    )) { error in
      guard let issuanceError = error as? CredentialIssuanceError else {
        XCTFail("Expected CredentialIssuanceError")
        return
      }
      if case .proofTypeJwtWithoutKeyAttestationNotAllowedByPolicy = issuanceError {
        // Expected error
      } else {
        XCTFail("Expected proofTypeJwtWithoutKeyAttestationNotAllowedByPolicy error")
      }
    }
  }

  func testAcceptAllPolicy_AcceptsJwtWithoutKeyAttestation() throws {
    let policy = ProofTypesPolicy.acceptAll

    // Credential requires JWT without key attestation
    let proofTypesSupported: [String: ProofTypeSupportedMeta] = [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .notRequired
      )
    ]
    let credentialConfig = createTestCredentialConfiguration(proofTypesSupported: proofTypesSupported)
    let bindingKey = try createJwtBindingKey()

    // Should not throw with acceptAll policy
    XCTAssertNoThrow(try policy.validate(
      credentialConfiguration: credentialConfig,
      bindingKey: bindingKey
    ))
  }

  // MARK: - Validation Tests - JWT With Key Attestation

  func testDeviceBoundPolicy_AcceptsJwtWithKeyAttestation() throws {
    let deviceBoundPolicy = DeviceBoundProofPolicy(
      supportedAlgorithms: [JWSAlgorithm(.ES256)],
      supportedProofTypes: [.jwtWithKeyAttestation]
    )
    let policy = ProofTypesPolicy.deviceBound(deviceBoundPolicy)

    // Credential requires JWT with key attestation
    let proofTypesSupported: [String: ProofTypeSupportedMeta] = [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .required(
          keyStorageConstraints: [.iso18045High],
          userAuthenticationConstraints: [.iso18045Moderate],
          preferredKeyStorageStatusPeriod: nil
        )
      )
    ]
    let credentialConfig = createTestCredentialConfiguration(proofTypesSupported: proofTypesSupported)
    let bindingKey = try createJwtKeyAttestationBindingKey()

    // Should not throw
    XCTAssertNoThrow(try policy.validate(
      credentialConfiguration: credentialConfig,
      bindingKey: bindingKey
    ))
  }

  func testDeviceBoundPolicy_RejectsJwtWithKeyAttestation_WhenNotInSupportedProofTypes() throws {
    let deviceBoundPolicy = DeviceBoundProofPolicy(
      supportedAlgorithms: [JWSAlgorithm(.ES256)],
      supportedProofTypes: [.attestation] // Only attestation, not JWT with key attestation
    )
    let policy = ProofTypesPolicy.deviceBound(deviceBoundPolicy)

    // Credential requires JWT with key attestation
    let proofTypesSupported: [String: ProofTypeSupportedMeta] = [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .required(
          keyStorageConstraints: [.iso18045High],
          userAuthenticationConstraints: [.iso18045Moderate],
          preferredKeyStorageStatusPeriod: nil
        )
      )
    ]
    let credentialConfig = createTestCredentialConfiguration(proofTypesSupported: proofTypesSupported)
    let bindingKey = try createJwtKeyAttestationBindingKey()

    // Should throw because policy doesn't support JWT with key attestation
    XCTAssertThrowsError(try policy.validate(
      credentialConfiguration: credentialConfig,
      bindingKey: bindingKey
    )) { error in
      guard let issuanceError = error as? CredentialIssuanceError else {
        XCTFail("Expected CredentialIssuanceError")
        return
      }
      if case .proofTypeNotSupportedByWalletPolicy = issuanceError {
        // Expected error
      } else {
        XCTFail("Expected proofTypeNotSupportedByWalletPolicy error")
      }
    }
  }

  func testDeviceBoundPolicy_RejectsJwtWithKeyAttestation_WhenBindingKeyNotAttestationCapable() throws {
    let deviceBoundPolicy = DeviceBoundProofPolicy(
      supportedAlgorithms: [JWSAlgorithm(.ES256)],
      supportedProofTypes: [.jwtWithKeyAttestation]
    )
    let policy = ProofTypesPolicy.deviceBound(deviceBoundPolicy)

    // Credential requires JWT with key attestation
    let proofTypesSupported: [String: ProofTypeSupportedMeta] = [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: .required(
          keyStorageConstraints: [.iso18045High],
          userAuthenticationConstraints: [.iso18045Moderate],
          preferredKeyStorageStatusPeriod: nil
        )
      )
    ]
    let credentialConfig = createTestCredentialConfiguration(proofTypesSupported: proofTypesSupported)
    // Use a plain JWT binding key (not attestation-capable)
    let bindingKey = try createJwtBindingKey()

    // Should throw because binding key is not attestation-capable
    XCTAssertThrowsError(try policy.validate(
      credentialConfiguration: credentialConfig,
      bindingKey: bindingKey
    )) { error in
      guard let issuanceError = error as? CredentialIssuanceError else {
        XCTFail("Expected CredentialIssuanceError")
        return
      }
      if case .bindingKeyNotAttestationCapable = issuanceError {
        // Expected error
      } else {
        XCTFail("Expected bindingKeyNotAttestationCapable error")
      }
    }
  }

  // MARK: - Validation Tests - Attestation Proof Type

  func testDeviceBoundPolicy_AcceptsAttestationProof() throws {
    let deviceBoundPolicy = DeviceBoundProofPolicy(
      supportedAlgorithms: [JWSAlgorithm(.ES256)],
      supportedProofTypes: [.attestation]
    )
    let policy = ProofTypesPolicy.deviceBound(deviceBoundPolicy)

    // Credential requires attestation proof
    let proofTypesSupported: [String: ProofTypeSupportedMeta] = [
      "attestation": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: nil
      )
    ]
    let credentialConfig = createTestCredentialConfiguration(proofTypesSupported: proofTypesSupported)
    let bindingKey = try createAttestationBindingKey()

    // Should not throw
    XCTAssertNoThrow(try policy.validate(
      credentialConfiguration: credentialConfig,
      bindingKey: bindingKey
    ))
  }

  func testDeviceBoundPolicy_RejectsAttestationProof_WhenNotInSupportedProofTypes() throws {
    let deviceBoundPolicy = DeviceBoundProofPolicy(
      supportedAlgorithms: [JWSAlgorithm(.ES256)],
      supportedProofTypes: [.jwtWithKeyAttestation] // Only JWT with key attestation
    )
    let policy = ProofTypesPolicy.deviceBound(deviceBoundPolicy)

    // Credential requires attestation proof
    let proofTypesSupported: [String: ProofTypeSupportedMeta] = [
      "attestation": ProofTypeSupportedMeta(
        algorithms: ["ES256"],
        keyAttestationRequirement: nil
      )
    ]
    let credentialConfig = createTestCredentialConfiguration(proofTypesSupported: proofTypesSupported)
    let bindingKey = try createAttestationBindingKey()

    // Should throw because policy doesn't support attestation proofs
    XCTAssertThrowsError(try policy.validate(
      credentialConfiguration: credentialConfig,
      bindingKey: bindingKey
    )) { error in
      guard let issuanceError = error as? CredentialIssuanceError else {
        XCTFail("Expected CredentialIssuanceError")
        return
      }
      if case .proofTypeNotSupportedByWalletPolicy = issuanceError {
        // Expected error
      } else {
        XCTFail("Expected proofTypeNotSupportedByWalletPolicy error")
      }
    }
  }

  // MARK: - Algorithm Matching Tests

  func testDeviceBoundPolicy_RejectsWhenNoMatchingAlgorithm() throws {
    let deviceBoundPolicy = DeviceBoundProofPolicy(
      supportedAlgorithms: [JWSAlgorithm(.ES384)], // Only ES384
      supportedProofTypes: [.jwtWithKeyAttestation]
    )
    let policy = ProofTypesPolicy.deviceBound(deviceBoundPolicy)

    // Credential requires ES256
    let proofTypesSupported: [String: ProofTypeSupportedMeta] = [
      "jwt": ProofTypeSupportedMeta(
        algorithms: ["ES256"], // Different algorithm
        keyAttestationRequirement: .required(
          keyStorageConstraints: [.iso18045High],
          userAuthenticationConstraints: [.iso18045Moderate],
          preferredKeyStorageStatusPeriod: nil
        )
      )
    ]
    let credentialConfig = createTestCredentialConfiguration(proofTypesSupported: proofTypesSupported)
    let bindingKey = try createJwtKeyAttestationBindingKey()

    // Should throw because no matching algorithm
    XCTAssertThrowsError(try policy.validate(
      credentialConfiguration: credentialConfig,
      bindingKey: bindingKey
    )) { error in
      guard let issuanceError = error as? CredentialIssuanceError else {
        XCTFail("Expected CredentialIssuanceError")
        return
      }
      if case .noMatchingAlgorithmForProofType = issuanceError {
        // Expected error
      } else {
        XCTFail("Expected noMatchingAlgorithmForProofType error")
      }
    }
  }

  // MARK: - Flexible Policy Tests

  func testFlexiblePolicy_AllowsNonDeviceBound() throws {
    let deviceBoundPolicy = DeviceBoundProofPolicy(
      supportedAlgorithms: [JWSAlgorithm(.ES256)],
      supportedProofTypes: [.jwtWithKeyAttestation]
    )
    let policy = ProofTypesPolicy.flexible(
      deviceBound: deviceBoundPolicy,
      allowNonDeviceBound: true
    )

    // Credential without proof types (non-device-bound)
    let credentialConfig = createTestCredentialConfiguration(proofTypesSupported: nil)
    let bindingKey = try createJwtBindingKey()

    // Should not throw because non-device-bound is allowed
    XCTAssertNoThrow(try policy.validate(
      credentialConfiguration: credentialConfig,
      bindingKey: bindingKey
    ))
  }

  func testFlexiblePolicy_RejectsNonDeviceBound_WhenNotAllowed() throws {
    let deviceBoundPolicy = DeviceBoundProofPolicy(
      supportedAlgorithms: [JWSAlgorithm(.ES256)],
      supportedProofTypes: [.jwtWithKeyAttestation]
    )
    let policy = ProofTypesPolicy.flexible(
      deviceBound: deviceBoundPolicy,
      allowNonDeviceBound: false
    )

    // Credential without proof types (non-device-bound)
    let credentialConfig = createTestCredentialConfiguration(proofTypesSupported: nil)
    let bindingKey = try createJwtBindingKey()

    // Should throw because non-device-bound is not allowed
    XCTAssertThrowsError(try policy.validate(
      credentialConfiguration: credentialConfig,
      bindingKey: bindingKey
    )) { error in
      guard let issuanceError = error as? CredentialIssuanceError else {
        XCTFail("Expected CredentialIssuanceError")
        return
      }
      if case .proofTypesNotSupportedByCredentialConfiguration = issuanceError {
        // Expected error
      } else {
        XCTFail("Expected proofTypesNotSupportedByCredentialConfiguration error")
      }
    }
  }

  // MARK: - Helper Methods

  private func createTestCredentialConfiguration(
    proofTypesSupported: [String: ProofTypeSupportedMeta]?
  ) -> CredentialSupported {
    let credentialDefinition = SdJwtVcFormat.CredentialDefinition(
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
      credentialDefinition: credentialDefinition
    )
    return .sdJwtVc(config)
  }

  private func createJwtBindingKey() throws -> BindingKey {
    let privateKey = try KeyController.generateECDHPrivateKey()
    let publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
    let jwk = try ECPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "use": "sig",
        "kid": "test-key-1",
        "alg": JWSAlgorithm(.ES256).name
      ]
    )

    return .jwt(
      algorithm: JWSAlgorithm(.ES256),
      jwk: jwk,
      privateKey: .secKey(privateKey),
      issuer: nil
    )
  }

  private func createJwtKeyAttestationBindingKey() throws -> BindingKey {
    let privateKey = try KeyController.generateECDHPrivateKey()

    // Mock compact JWS string for testing
    let mockJWSString = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtleS1hdHRlc3RhdGlvbitqd3QifQ.eyJ0ZXN0IjoiZGF0YSJ9.mock_signature"

    return .jwtKeyAttestation(
      algorithm: JWSAlgorithm(.ES256),
      keyAttestationJWT: { _ in
        // Mock key attestation JWT using compact serialization
        try KeyAttestationJWT(
          jws: JWS(compactSerialization: mockJWSString)
        )
      },
      keyIndex: 0,
      privateKey: .secKey(privateKey),
      issuer: nil
    )
  }

  private func createAttestationBindingKey() throws -> BindingKey {
    // Mock compact JWS string for testing
    let mockJWSString = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtleS1hdHRlc3RhdGlvbitqd3QifQ.eyJ0ZXN0IjoiZGF0YSJ9.mock_signature"

    return .attestation(
      keyAttestationJWT: { _ in
        // Mock key attestation JWT using compact serialization
        try KeyAttestationJWT(
          jws: JWS(compactSerialization: mockJWSString)
        )
      }
    )
  }
}
