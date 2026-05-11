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

/// Validator for credential reuse policies according to ETSI TS 119 472-3 and ARF Annex II
public struct CredentialReusePolicyValidator {

  /// Validates issuer policy against wallet capabilities and selects best matching option
  /// - Parameters:
  ///   - issuerPolicy: The reuse policy from issuer metadata (optional)
  ///   - walletSupported: Wallet's supported reuse policy configuration
  /// - Returns: Selected policy that matches wallet capabilities, or nil if no policy and not required
  /// - Throws: CredentialReusePolicyError if validation fails or no match found
  public static func selectMatchingPolicy(
    issuerPolicy: CredentialReusePolicy?,
    walletSupported: SupportedCredentialReusePolicies
  ) throws -> ReusePolicy? {

    try walletSupported.validate()

    if issuerPolicy == nil {
      switch walletSupported {
      case .required:
        throw CredentialReusePolicyError.noSupportedPolicyFound
      case .supported, .notSupported:
        return nil
      }
    }

    guard let policy = issuerPolicy else {
      return nil
    }

    if case .notSupported = walletSupported {
      // Issuer has policy but wallet doesn't support policies → ignore and continue
      return nil
    }

    guard policy.id == "arf_annex_ii" else {
      throw CredentialReusePolicyError.unsupportedPolicyId(policy.id)
    }

    guard !policy.options.isEmpty else {
      throw CredentialReusePolicyError.invalidPolicyStructure("options array is empty")
    }

    guard let walletMethods = walletSupported.supportedMethods else {
      throw CredentialReusePolicyError.noSupportedPolicyFound
    }

    // Find first policy that wallet supports (respecting issuer's priority order)
    for option in policy.options {
      if walletMethods.contains(option.method) {
        return option
      }
    }

    // No compatible option found - both have policies but no match → error
    throw CredentialReusePolicyError.noSupportedPolicyFound
  }

  /// Determines the batch size to use for credential issuance
  /// Priority: reuse policy batch size > batch_credential_issuance from metadata
  /// - Parameters:
  ///   - selectedPolicy: The selected reuse policy (if any)
  ///   - issuerBatchSize: The batch_credential_issuance from issuer metadata (if any)
  /// - Returns: Batch size to use, or nil if no batch issuance
  public static func determineBatchSize(
    selectedPolicy: ReusePolicy?,
    issuerBatchSize: Int?
  ) -> Int? {
    // Priority 1: Reuse policy batch size (if present)
    if let policyBatchSize = selectedPolicy?.batchSize {
      return policyBatchSize
    }

    // Priority 2: Fallback to batch_credential_issuance
    return issuerBatchSize
  }

  /// Validates that the number of proofs matches the required batch size
  /// - Parameters:
  ///   - proofCount: Number of proofs being submitted
  ///   - requiredBatchSize: Required batch size from policy or issuer metadata
  /// - Throws: CredentialReusePolicyError.batchSizeMismatch if counts don't match
  public static func validateProofCount(
    proofCount: Int,
    requiredBatchSize: Int?
  ) throws {
    guard let requiredSize = requiredBatchSize else {
      // No batch size requirement
      return
    }

    guard proofCount == requiredSize else {
      throw CredentialReusePolicyError.batchSizeMismatch(
        required: requiredSize,
        provided: proofCount
      )
    }
  }
}
