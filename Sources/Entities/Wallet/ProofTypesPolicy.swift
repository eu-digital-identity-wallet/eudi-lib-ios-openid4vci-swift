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
import JOSESwift

/// Policy defining which proof types the wallet supports for credential issuance.
///
/// For device-bound attestations, proofs of type JWT cannot be used alone
/// - Wallet must use either:
///   - Proof of type `attestation`
///   - Proof of type `jwt` + `key_attestation`
/// - Plain JWT proofs (without key_attestation) are not allowed for device-bound credentials
public enum ProofTypesPolicy: Sendable {
  /// Default policy: accepts any proof type including plain JWT without key attestation.
  /// This is the legacy behavior for backward compatibility.
  case acceptAll

  /// Rejects credential configurations that require plain JWT proofs without key attestation.
  /// - Parameter policy: The device-bound proof policy specifying supported algorithms and proof types.
  case deviceBound(DeviceBoundProofPolicy)

  /// Flexible policy: supports both device-bound and non-device-bound attestations.
  /// - Parameters:
  ///   - deviceBound: Policy for device-bound credentials
  ///   - allowNonDeviceBound: Whether to allow non-device-bound credentials (no proofs required)
  case flexible(deviceBound: DeviceBoundProofPolicy, allowNonDeviceBound: Bool)
}

/// Policy configuration for device-bound proof types.
public struct DeviceBoundProofPolicy: Sendable {
  public let supportedAlgorithms: [JWSAlgorithm]
  public let supportedProofTypes: Set<DeviceBoundProofType>

  public init(
    supportedAlgorithms: [JWSAlgorithm],
    supportedProofTypes: Set<DeviceBoundProofType>
  ) {
    self.supportedAlgorithms = supportedAlgorithms
    self.supportedProofTypes = supportedProofTypes
  }

  /// Creates a HAIP compliant policy.
  /// This policy only accepts JWT with key attestation or attestation proofs.
  /// - Parameter algorithms: Supported signing algorithms. Defaults to ES256.
  /// - Returns: A compliant device-bound proof policy.
  public static func haipCompliant(
    algorithms: [JWSAlgorithm] = [JWSAlgorithm(.ES256)]
  ) -> DeviceBoundProofPolicy {
    return DeviceBoundProofPolicy(
      supportedAlgorithms: algorithms,
      supportedProofTypes: [.jwtWithKeyAttestation, .attestation]
    )
  }
}

/// Types of proofs for device-bound credentials.
public enum DeviceBoundProofType: String, Hashable, Sendable {
  
  case jwtWithoutKeyAttestation = "jwt_without_key_attestation"
  case jwtWithKeyAttestation = "jwt_with_key_attestation"
  case attestation = "attestation"
}

// MARK: - Validation

public extension ProofTypesPolicy {

  /// Validates whether a credential configuration is compatible with this policy.
  ///
  /// - Parameters:
  ///   - credentialConfiguration: The credential configuration to validate.
  ///   - bindingKey: The binding key that will be used for the proof.
  /// - Throws: `CredentialIssuanceError` if the configuration violates the policy.
  func validate(
    credentialConfiguration: CredentialSupported,
    bindingKey: BindingKey
  ) throws {
    switch self {
    case .acceptAll:
      // Accept everything - no validation needed
      return

    case .deviceBound(let policy):
      try validateDeviceBound(
        credentialConfiguration: credentialConfiguration,
        policy: policy,
        bindingKey: bindingKey,
        allowNonDeviceBound: false
      )

    case .flexible(let policy, let allowNonDeviceBound):
      try validateDeviceBound(
        credentialConfiguration: credentialConfiguration,
        policy: policy,
        bindingKey: bindingKey,
        allowNonDeviceBound: allowNonDeviceBound
      )
    }
  }

  private func validateDeviceBound(
    credentialConfiguration: CredentialSupported,
    policy: DeviceBoundProofPolicy,
    bindingKey: BindingKey,
    allowNonDeviceBound: Bool
  ) throws {
    guard let proofTypesSupported = credentialConfiguration.proofTypesSupported else {
      if allowNonDeviceBound {
        return
      } else {
        throw CredentialIssuanceError.proofTypesNotSupportedByCredentialConfiguration
      }
    }

    if let jwtProofMeta = proofTypesSupported["jwt"] {
      try validateJwtProof(
        jwtProofMeta: jwtProofMeta,
        policy: policy,
        bindingKey: bindingKey
      )
    }

    if let attestationProofMeta = proofTypesSupported["attestation"] {
      try validateAttestationProof(
        attestationProofMeta: attestationProofMeta,
        policy: policy,
        bindingKey: bindingKey
      )
    }
  }

  private func validateJwtProof(
    jwtProofMeta: ProofTypeSupportedMeta,
    policy: DeviceBoundProofPolicy,
    bindingKey: BindingKey
  ) throws {
    
    let hasMatchingAlgorithm = jwtProofMeta.algorithms.contains { issuerAlg in
      policy.supportedAlgorithms.contains { walletAlg in
        walletAlg.name == issuerAlg
      }
    }

    guard hasMatchingAlgorithm else {
      throw CredentialIssuanceError.noMatchingAlgorithmForProofType
    }

    // Determine if key attestation is required
    let keyAttestationRequired = jwtProofMeta.keyAttestationRequirement != nil &&
                                 jwtProofMeta.keyAttestationRequirement != .notRequired

    if keyAttestationRequired {
      // Issuer requires key attestation - check if wallet policy supports it
      guard policy.supportedProofTypes.contains(.jwtWithKeyAttestation) else {
        throw CredentialIssuanceError.proofTypeNotSupportedByWalletPolicy
      }

      // Check if the binding key is attestation-capable
      guard bindingKey.isAttestationCapable else {
        throw CredentialIssuanceError.bindingKeyNotAttestationCapable
      }
    } else {
      // Issuer allows plain JWT without key attestation
      // Check if wallet policy allows this
      guard policy.supportedProofTypes.contains(.jwtWithoutKeyAttestation) else {
        throw CredentialIssuanceError.proofTypeJwtWithoutKeyAttestationNotAllowedByPolicy
      }
    }
  }

  private func validateAttestationProof(
    attestationProofMeta: ProofTypeSupportedMeta,
    policy: DeviceBoundProofPolicy,
    bindingKey: BindingKey
  ) throws {
    guard policy.supportedProofTypes.contains(.attestation) else {
      throw CredentialIssuanceError.proofTypeNotSupportedByWalletPolicy
    }

    guard bindingKey.isAttestationCapable else {
      throw CredentialIssuanceError.bindingKeyNotAttestationCapable
    }

    let hasMatchingAlgorithm = attestationProofMeta.algorithms.contains { issuerAlg in
      policy.supportedAlgorithms.contains { walletAlg in
        walletAlg.name == issuerAlg
      }
    }

    guard hasMatchingAlgorithm else {
      throw CredentialIssuanceError.noMatchingAlgorithmForProofType
    }
  }
}
