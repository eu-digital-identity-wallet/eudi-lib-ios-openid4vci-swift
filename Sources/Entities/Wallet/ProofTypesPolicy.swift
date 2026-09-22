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

/// Proof types accepted by the wallet for attested credentials.
///
public enum AttestedProofType: String, Hashable, Sendable {
  case jwtWithKeyAttestation = "jwt_with_key_attestation"
  case attestation = "attestation"
}

/// Policy configuration for strict (HAIP-compliant) proof types.
/// Only attested proof types are accepted.
public struct StrictProofPolicy: Sendable {
  public let supportedAlgorithms: [JWSAlgorithm]
  public let supportedProofTypes: Set<AttestedProofType>

  public init(
    supportedAlgorithms: [JWSAlgorithm],
    supportedProofTypes: Set<AttestedProofType>
  ) {
    self.supportedAlgorithms = supportedAlgorithms
    self.supportedProofTypes = supportedProofTypes
  }
}

/// Policy configuration for flexible proof types.
/// Allows custom configuration supporting both attested and plain JWT proofs.
public struct FlexibleProofPolicy: Sendable {
  public let supportedAlgorithms: [JWSAlgorithm]
  public let supportedAttestedProofTypes: Set<AttestedProofType>
  public let allowPlainJwtProof: Bool

  public init(
    supportedAlgorithms: [JWSAlgorithm],
    supportedAttestedProofTypes: Set<AttestedProofType>,
    allowPlainJwtProof: Bool
  ) {
    self.supportedAlgorithms = supportedAlgorithms
    self.supportedAttestedProofTypes = supportedAttestedProofTypes
    self.allowPlainJwtProof = allowPlainJwtProof
  }
}

/// Wallet's policy for credential-request proofs.
///
/// Defines which proof types the wallet supports for credential issuance.
/// - For device-bound attestations (HAIP-compliant), use `.strict` or `.haipCompliant()`.
/// - For testing or legacy compatibility, use `.acceptAll` to allow plain JWT proofs.
/// - For custom configurations, use `.flexible` with specific settings.
public enum ProofTypesPolicy: Sendable {

  /// Strict HAIP-compliant policy: only attested proof types are allowed.
  /// Rejects issuers that don't advertise `key_attestations_required`.
  case strict(StrictProofPolicy)

  /// Accepts any proof type including plain JWT without key attestation.
  /// For testing or legacy compatibility with non-HAIP issuers.
  case acceptAll(supportedAlgorithms: [JWSAlgorithm])

  /// Flexible policy with custom settings.
  /// Allows fine-grained control over which proof types are accepted.
  case flexible(FlexibleProofPolicy)

  /// HAIP-compliant strict policy: ES256 with both attested proof types.
  /// This is the recommended policy for production use.
  public static func haipCompliant(
    algorithms: [JWSAlgorithm] = [JWSAlgorithm(.ES256)]
  ) -> ProofTypesPolicy {
    return .strict(StrictProofPolicy(
      supportedAlgorithms: algorithms,
      supportedProofTypes: [.jwtWithKeyAttestation, .attestation]
    ))
  }
}

// MARK: - Validation

public extension ProofTypesPolicy {

  /// Returns the supported algorithms for this policy.
  var supportedAlgorithms: [JWSAlgorithm] {
    switch self {
    case .strict(let policy):
      return policy.supportedAlgorithms
    case .acceptAll(let algorithms):
      return algorithms
    case .flexible(let policy):
      return policy.supportedAlgorithms
    }
  }

  /// Validates issuer metadata for a credential configuration up front, before
  /// any binding key is built.
  ///
  /// Behavior varies by policy type:
  /// - `.strict`: Requires issuer to advertise attested proof types with `key_attestations_required`.
  /// - `.acceptAll`: Accepts any proof type configuration, including plain JWT.
  /// - `.flexible`: Depends on `allowPlainJwtProof` setting.
  ///
  /// Rules for strict policy:
  ///   - If `proof_types_supported` is missing or empty, the configuration
  ///     does not require a proof; this method returns successfully.
  ///   - Otherwise, the configuration MUST advertise at least one of
  ///     `proof_type: jwt` or `proof_type: attestation` with
  ///     `key_attestations_required`.
  ///   - At least one of the advertised attested proof types must be in the
  ///     wallet's `supportedProofTypes`, with at least one matching algorithm.
  ///
  /// Throws:
  ///   - `CredentialIssuanceError.issuerMetadataNoAttestedProofType` when the
  ///     metadata invariant is violated (strict policy only).
  ///   - `CredentialIssuanceError.proofTypeNotSupportedByWalletPolicy` when no
  ///     advertised type intersects the wallet's supported types.
  ///   - `CredentialIssuanceError.noMatchingAlgorithmForProofType` when no
  ///     advertised algorithm intersects the wallet's `supportedAlgorithms`.
  func validateIssuerMetadata(
    credentialConfiguration: CredentialSupported
  ) throws {
    switch self {
    case .strict(let policy):
      try validateStrictPolicy(
        policy: policy,
        credentialConfiguration: credentialConfiguration
      )

    case .acceptAll(let algorithms):
      try validateAcceptAllPolicy(
        algorithms: algorithms,
        credentialConfiguration: credentialConfiguration
      )

    case .flexible(let policy):
      try validateFlexiblePolicy(
        policy: policy,
        credentialConfiguration: credentialConfiguration
      )
    }
  }

  /// Validates that a chosen binding key is compatible with the credential
  /// configuration.
  func validate(
    credentialConfiguration: CredentialSupported,
    bindingKey: BindingKey
  ) throws {
    try validateIssuerMetadata(credentialConfiguration: credentialConfiguration)

    switch self {
    case .strict:
      // Strict policy requires attestation-capable binding keys
      guard bindingKey.isAttestationCapable else {
        throw CredentialIssuanceError.bindingKeyNotAttestationCapable
      }

    case .acceptAll:
      // Accept all policy allows any binding key, but must match issuer requirements
      try validateBindingKeyMatchesIssuerRequirements(
        credentialConfiguration: credentialConfiguration,
        bindingKey: bindingKey
      )

    case .flexible(let policy):
      if policy.allowPlainJwtProof {
        // Flexible with plain JWT allowed - validate against issuer requirements
        try validateBindingKeyMatchesIssuerRequirements(
          credentialConfiguration: credentialConfiguration,
          bindingKey: bindingKey
        )
      } else {
        // Flexible without plain JWT - require attestation capability
        guard bindingKey.isAttestationCapable else {
          throw CredentialIssuanceError.bindingKeyNotAttestationCapable
        }
      }
    }
  }

  // MARK: - Private Validation Methods

  private func validateStrictPolicy(
    policy: StrictProofPolicy,
    credentialConfiguration: CredentialSupported
  ) throws {
    guard let proofTypesSupported = credentialConfiguration.proofTypesSupported,
          !proofTypesSupported.isEmpty else {
      return
    }

    let attestedCandidates: [(AttestedProofType, ProofTypeSupportedMeta)] = [
      ("jwt", .jwtWithKeyAttestation),
      ("attestation", .attestation)
    ].compactMap { key, type in
      guard let meta = proofTypesSupported[key],
            Self.requiresKeyAttestation(meta) else { return nil }
      return (type, meta)
    }

    guard !attestedCandidates.isEmpty else {
      throw CredentialIssuanceError.issuerMetadataNoAttestedProofType
    }

    let walletSupported = attestedCandidates.filter {
      policy.supportedProofTypes.contains($0.0)
    }

    guard !walletSupported.isEmpty else {
      throw CredentialIssuanceError.proofTypeNotSupportedByWalletPolicy
    }

    let hasMatchingAlgorithm = walletSupported.contains { (_, meta) in
      meta.algorithms.contains { issuerAlg in
        policy.supportedAlgorithms.contains { walletAlg in
          walletAlg.name == issuerAlg
        }
      }
    }
    guard hasMatchingAlgorithm else {
      throw CredentialIssuanceError.noMatchingAlgorithmForProofType
    }
  }

  private func validateAcceptAllPolicy(
    algorithms: [JWSAlgorithm],
    credentialConfiguration: CredentialSupported
  ) throws {
    guard let proofTypesSupported = credentialConfiguration.proofTypesSupported,
          !proofTypesSupported.isEmpty else {
      return
    }

    // For acceptAll, we just need to verify algorithm compatibility
    // with any advertised proof type (jwt or attestation)
    let hasMatchingAlgorithm = proofTypesSupported.values.contains { meta in
      meta.algorithms.contains { issuerAlg in
        algorithms.contains { walletAlg in
          walletAlg.name == issuerAlg
        }
      }
    }

    guard hasMatchingAlgorithm else {
      throw CredentialIssuanceError.noMatchingAlgorithmForProofType
    }
  }

  private func validateFlexiblePolicy(
    policy: FlexibleProofPolicy,
    credentialConfiguration: CredentialSupported
  ) throws {
    guard let proofTypesSupported = credentialConfiguration.proofTypesSupported,
          !proofTypesSupported.isEmpty else {
      return
    }

    // Check for attested proof types first
    let attestedCandidates: [(AttestedProofType, ProofTypeSupportedMeta)] = [
      ("jwt", .jwtWithKeyAttestation),
      ("attestation", .attestation)
    ].compactMap { key, type in
      guard let meta = proofTypesSupported[key],
            Self.requiresKeyAttestation(meta) else { return nil }
      return (type, meta)
    }

    let walletSupportedAttested = attestedCandidates.filter {
      policy.supportedAttestedProofTypes.contains($0.0)
    }

    // Check for plain JWT if allowed
    var hasPlainJwtOption = false
    if policy.allowPlainJwtProof {
      if let jwtMeta = proofTypesSupported["jwt"],
         !Self.requiresKeyAttestation(jwtMeta) {
        hasPlainJwtOption = true
      }
    }

    // Must have at least one valid option
    guard !walletSupportedAttested.isEmpty || hasPlainJwtOption else {
      if attestedCandidates.isEmpty && !hasPlainJwtOption {
        throw CredentialIssuanceError.issuerMetadataNoAttestedProofType
      }
      throw CredentialIssuanceError.proofTypeNotSupportedByWalletPolicy
    }

    // Check algorithm compatibility
    var hasMatchingAlgorithm = false

    if !walletSupportedAttested.isEmpty {
      hasMatchingAlgorithm = walletSupportedAttested.contains { (_, meta) in
        meta.algorithms.contains { issuerAlg in
          policy.supportedAlgorithms.contains { walletAlg in
            walletAlg.name == issuerAlg
          }
        }
      }
    }

    if !hasMatchingAlgorithm && hasPlainJwtOption {
      if let jwtMeta = proofTypesSupported["jwt"] {
        hasMatchingAlgorithm = jwtMeta.algorithms.contains { issuerAlg in
          policy.supportedAlgorithms.contains { walletAlg in
            walletAlg.name == issuerAlg
          }
        }
      }
    }

    guard hasMatchingAlgorithm else {
      throw CredentialIssuanceError.noMatchingAlgorithmForProofType
    }
  }

  private func validateBindingKeyMatchesIssuerRequirements(
    credentialConfiguration: CredentialSupported,
    bindingKey: BindingKey
  ) throws {
    guard let proofTypesSupported = credentialConfiguration.proofTypesSupported,
          !proofTypesSupported.isEmpty else {
      return
    }

    // If issuer requires key attestation for JWT, binding key must be attestation-capable
    if let jwtMeta = proofTypesSupported["jwt"],
       Self.requiresKeyAttestation(jwtMeta) {
      // Issuer requires attestation - check if wallet is using plain JWT binding
      if case .jwt = bindingKey {
        throw CredentialIssuanceError.proofTypeKeyAttestationRequired
      }
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
