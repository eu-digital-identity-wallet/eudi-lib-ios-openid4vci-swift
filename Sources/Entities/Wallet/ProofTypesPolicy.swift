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

/// Proof types accepted by the wallet.
///
public enum AttestedProofType: String, Hashable, Sendable {
  case jwtWithKeyAttestation = "jwt_with_key_attestation"
  case attestation = "attestation"
}

/// Wallet's policy for credential-request proofs.
///
/// Defines which signing algorithms and which attested proof types the wallet
/// is willing to produce. Used to validate that the issuer's
/// `proof_types_supported` advertises a compatible option.
public struct ProofTypesPolicy: Sendable {
  public let supportedAlgorithms: [JWSAlgorithm]
  public let supportedProofTypes: Set<AttestedProofType>

  public init(
    supportedAlgorithms: [JWSAlgorithm],
    supportedProofTypes: Set<AttestedProofType>
  ) {
    self.supportedAlgorithms = supportedAlgorithms
    self.supportedProofTypes = supportedProofTypes
  }

  /// HAIP-compliant policy: ES256 with both attested proof types.
  public static func haipCompliant(
    algorithms: [JWSAlgorithm] = [JWSAlgorithm(.ES256)]
  ) -> ProofTypesPolicy {
    return ProofTypesPolicy(
      supportedAlgorithms: algorithms,
      supportedProofTypes: [.jwtWithKeyAttestation, .attestation]
    )
  }
}

// MARK: - Validation

public extension ProofTypesPolicy {

  /// Validates issuer metadata for a credential configuration up front, before
  /// any binding key is built.
  ///
  /// Rules
  ///   - If `proof_types_supported` is missing or empty, the configuration
  ///     does not require a proof; this method returns successfully.
  ///   - Otherwise, the configuration MUST advertise BOTH `proof_type: jwt`
  ///     AND `proof_type: attestation`, and BOTH MUST carry
  ///     `key_attestations_required`.
  ///   - At least one of the two advertised attested proof types must be in
  ///     the wallet's `supportedProofTypes`, with at least one matching
  ///     algorithm in `supportedAlgorithms`.
  ///
  /// Throws:
  ///   - `CredentialIssuanceError.issuerMetadataNoAttestedProofType` when the
  ///     metadata invariant is violated.
  ///   - `CredentialIssuanceError.proofTypeNotSupportedByWalletPolicy` when no
  ///     advertised type intersects the wallet's `supportedProofTypes`.
  ///   - `CredentialIssuanceError.noMatchingAlgorithmForProofType` when no
  ///     advertised algorithm intersects the wallet's `supportedAlgorithms`.
  func validateIssuerMetadata(
    credentialConfiguration: CredentialSupported
  ) throws {
    guard let proofTypesSupported = credentialConfiguration.proofTypesSupported,
          !proofTypesSupported.isEmpty else {
      return
    }

    guard let jwtMeta = proofTypesSupported["jwt"],
          let attestationMeta = proofTypesSupported["attestation"],
          Self.requiresKeyAttestation(jwtMeta),
          Self.requiresKeyAttestation(attestationMeta) else {
      throw CredentialIssuanceError.issuerMetadataNoAttestedProofType
    }

    let walletSupported: [(AttestedProofType, ProofTypeSupportedMeta)] = [
      (.jwtWithKeyAttestation, jwtMeta),
      (.attestation, attestationMeta)
    ].filter { supportedProofTypes.contains($0.0) }

    guard !walletSupported.isEmpty else {
      throw CredentialIssuanceError.proofTypeNotSupportedByWalletPolicy
    }

    let hasMatchingAlgorithm = walletSupported.contains { (_, meta) in
      meta.algorithms.contains { issuerAlg in
        supportedAlgorithms.contains { walletAlg in
          walletAlg.name == issuerAlg
        }
      }
    }
    guard hasMatchingAlgorithm else {
      throw CredentialIssuanceError.noMatchingAlgorithmForProofType
    }
  }

  /// Validates that a chosen binding key is compatible with the credential
  /// configuration. Assumes `validateIssuerMetadata` has already succeeded.
  func validate(
    credentialConfiguration: CredentialSupported,
    bindingKey: BindingKey
  ) throws {
    try validateIssuerMetadata(credentialConfiguration: credentialConfiguration)

    guard bindingKey.isAttestationCapable else {
      throw CredentialIssuanceError.bindingKeyNotAttestationCapable
    }
  }

  private static func requiresKeyAttestation(_ meta: ProofTypeSupportedMeta) -> Bool {
    switch meta.keyAttestationRequirement {
    case .some(.required), .some(.requiredNoConstraints):
      return true
    default:
      return false
    }
  }
}
