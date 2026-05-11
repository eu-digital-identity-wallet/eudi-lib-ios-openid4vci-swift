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
@testable import OpenID4VCI

class ReusePolicyValidatorTests: XCTestCase {

  // MARK: - Policy Selection Tests

  func testSelectMatchingPolicy_ReturnsFirstMatchingPolicy() throws {
    let policy = CredentialReusePolicy(
      id: "arf_annex_ii",
      options: [
        .limitedTime(reissueTriggerLifetimeLeft: 885433),
        .onceOnly(batchSize: 10, reissueTriggerUnused: 4)
      ]
    )

    let walletConfig = SupportedCredentialReusePolicies.supported([.onceOnly])

    let selected = try CredentialReusePolicyValidator.selectMatchingPolicy(
      issuerPolicy: policy,
      walletSupported: walletConfig
    )

    // Wallet only supports onceOnly, should select the OnceOnly policy (second in list)
    if case .onceOnly(let batchSize, let reissueTriggerUnused) = selected {
      XCTAssertEqual(batchSize, 10)
      XCTAssertEqual(reissueTriggerUnused, 4)
    } else {
      XCTFail("Expected onceOnly policy")
    }
  }

  func testSelectMatchingPolicy_SelectsFirstWhenMultipleSupported() throws {
    let policy = CredentialReusePolicy(
      id: "arf_annex_ii",
      options: [
        .limitedTime(reissueTriggerLifetimeLeft: 885433),
        .rotatingBatch(batchSize: 40, reissueTriggerLifetimeLeft: 655433),
        .onceOnly(batchSize: 10, reissueTriggerUnused: 4)
      ]
    )

    // Wallet supports both limited_time and once_only
    let walletConfig = SupportedCredentialReusePolicies.supported([.limitedTime, .onceOnly])

    let selected = try CredentialReusePolicyValidator.selectMatchingPolicy(
      issuerPolicy: policy,
      walletSupported: walletConfig
    )

    // Should select first matching (limitedTime)
    if case .limitedTime(let reissueTriggerLifetimeLeft) = selected {
      XCTAssertEqual(reissueTriggerLifetimeLeft, 885433)
    } else {
      XCTFail("Expected limitedTime policy (first matching)")
    }
  }

  func testSelectMatchingPolicy_ThrowsWhenNoMatch() {
    let policy = CredentialReusePolicy(
      id: "arf_annex_ii",
      options: [
        .rotatingBatch(batchSize: 40, reissueTriggerLifetimeLeft: 655433),
        .perRelyingParty(batchSize: 60, reissueTriggerUnused: 10, reissueTriggerLifetimeLeft: 777543)
      ]
    )

    // Wallet only supports once_only (not in issuer's list)
    let walletConfig = SupportedCredentialReusePolicies.supported([.onceOnly])

    XCTAssertThrowsError(
      try CredentialReusePolicyValidator.selectMatchingPolicy(
        issuerPolicy: policy,
        walletSupported: walletConfig
      )
    ) { error in
      guard case CredentialReusePolicyError.noSupportedPolicyFound = error else {
        XCTFail("Expected noSupportedPolicyFound error")
        return
      }
    }
  }

  func testSelectMatchingPolicy_RequiredWallet_IssuerHasNoPolicy_Throws() {
    let walletConfig = SupportedCredentialReusePolicies.required([.onceOnly, .limitedTime])

    XCTAssertThrowsError(
      try CredentialReusePolicyValidator.selectMatchingPolicy(
        issuerPolicy: nil,
        walletSupported: walletConfig
      )
    ) { error in
      guard case CredentialReusePolicyError.noSupportedPolicyFound = error else {
        XCTFail("Expected noSupportedPolicyFound error")
        return
      }
    }
  }

  func testSelectMatchingPolicy_SupportedWallet_IssuerHasNoPolicy_ReturnsNil() throws {
    let walletConfig = SupportedCredentialReusePolicies.supported([.onceOnly, .limitedTime])

    let selected = try CredentialReusePolicyValidator.selectMatchingPolicy(
      issuerPolicy: nil,
      walletSupported: walletConfig
    )

    XCTAssertNil(selected)
  }

  func testSelectMatchingPolicy_NotSupportedWallet_IssuerHasPolicy_ReturnsNil() {
    let policy = CredentialReusePolicy(
      id: "arf_annex_ii",
      options: [
        .onceOnly(batchSize: 10, reissueTriggerUnused: 4)
      ]
    )

    let walletConfig = SupportedCredentialReusePolicies.notSupported

    XCTAssertNoThrow(
      try {
        let result = try CredentialReusePolicyValidator.selectMatchingPolicy(
          issuerPolicy: policy,
          walletSupported: walletConfig
        )
        XCTAssertNil(result, "Should return nil when wallet doesn't support policies")
      }()
    )
  }

  func testSelectMatchingPolicy_UnknownPolicyId_Throws() {
    let policy = CredentialReusePolicy(
      id: "some_unknown_policy",
      options: [
        .onceOnly(batchSize: 10, reissueTriggerUnused: 4)
      ]
    )

    let walletConfig = SupportedCredentialReusePolicies.supported([.onceOnly])

    XCTAssertThrowsError(
      try CredentialReusePolicyValidator.selectMatchingPolicy(
        issuerPolicy: policy,
        walletSupported: walletConfig
      )
    ) { error in
      guard case CredentialReusePolicyError.unsupportedPolicyId(let id) = error else {
        XCTFail("Expected unsupportedPolicyId error")
        return
      }
      XCTAssertEqual(id, "some_unknown_policy")
    }
  }

  // MARK: - Batch Size Determination Tests

  func testDetermineBatchSize_ReusePolicyWins() {
    let policy = ReusePolicy.onceOnly(batchSize: 10, reissueTriggerUnused: 4)
    let issuerBatchSize = 50

    let effectiveBatchSize = CredentialReusePolicyValidator.determineBatchSize(
      selectedPolicy: policy,
      issuerBatchSize: issuerBatchSize
    )

    XCTAssertEqual(effectiveBatchSize, 10) // Policy wins, not 50
  }

  func testDetermineBatchSize_FallbackToIssuerBatchSize() {
    let policy = ReusePolicy.limitedTime(reissueTriggerLifetimeLeft: 885433) // No batch size
    let issuerBatchSize = 50

    let effectiveBatchSize = CredentialReusePolicyValidator.determineBatchSize(
      selectedPolicy: policy,
      issuerBatchSize: issuerBatchSize
    )

    XCTAssertEqual(effectiveBatchSize, 50) // Fallback to issuer
  }

  func testDetermineBatchSize_NoBatchSize() {
    let effectiveBatchSize = CredentialReusePolicyValidator.determineBatchSize(
      selectedPolicy: nil,
      issuerBatchSize: nil
    )

    XCTAssertNil(effectiveBatchSize)
  }

  func testDetermineBatchSize_OnlyIssuerBatchSize() {
    let effectiveBatchSize = CredentialReusePolicyValidator.determineBatchSize(
      selectedPolicy: nil,
      issuerBatchSize: 25
    )

    XCTAssertEqual(effectiveBatchSize, 25)
  }

  // MARK: - Proof Count Validation Tests

  func testValidateProofCount_MatchingCount_Succeeds() {
    XCTAssertNoThrow(
      try CredentialReusePolicyValidator.validateProofCount(
        proofCount: 10,
        requiredBatchSize: 10
      )
    )
  }

  func testValidateProofCount_MismatchCount_Throws() {
    XCTAssertThrowsError(
      try CredentialReusePolicyValidator.validateProofCount(
        proofCount: 5,
        requiredBatchSize: 10
      )
    ) { error in
      guard case CredentialReusePolicyError.batchSizeMismatch(let required, let provided) = error else {
        XCTFail("Expected batchSizeMismatch error")
        return
      }
      XCTAssertEqual(required, 10)
      XCTAssertEqual(provided, 5)
    }
  }

  func testValidateProofCount_NoRequirement_Succeeds() {
    XCTAssertNoThrow(
      try CredentialReusePolicyValidator.validateProofCount(
        proofCount: 100,
        requiredBatchSize: nil
      )
    )
  }
}
