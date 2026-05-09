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
import SwiftyJSON

/// Tests for CredentialReusePolicy JSON parsing with details array expansion
class CredentialReusePolicyParsingTests: XCTestCase {

  // MARK: - Parsing Tests

  /// JSON has 1 option with 3 details -> Should expand to 3 policies
  func testParsing_PID_msoMdoc_ExpandsToThreePolicies() throws {
    let json = """
    {
      "format": "mso_mdoc",
      "scope": "PID_msoMdoc",
      "doctype": "eu.europa.ec.eudi.pid.1",
      "cryptographic_binding_methods_supported": ["jwk"],
      "credential_signing_alg_values_supported": [-7, -35, -36],
      "proof_types_supported": {
        "jwt": {
          "proof_signing_alg_values_supported": ["RS256", "ES256"]
        }
      },
      "credential_metadata": {
        "display": [{"name": "EU PID", "locale": "en-US"}],
        "credential_reuse_policy": {
          "id": "arf_annex_ii",
          "options": [{
            "details": ["limited_time", "rotating-batch", "per-relying-party"],
            "batch_size": 5,
            "reissue_trigger_lifetime_left": 655433,
            "reissue_trigger_unused": 3
          }]
        }
      }
    }
    """

    let data = json.data(using: .utf8)!
    let jsonObj = try JSON(data: data)
    let config = try MsoMdocFormat.CredentialConfiguration(json: jsonObj)

    let policy = try XCTUnwrap(config.credentialReusePolicy)

    XCTAssertEqual(policy.options.count, 3)

    // First: LimitedTime
    if case .limitedTime(let reissueTriggerLifetimeLeft) = policy.options[0] {
      XCTAssertEqual(reissueTriggerLifetimeLeft, 655433)
    } else {
      XCTFail("Expected limitedTime policy at index 0")
    }

    // Second: RotatingBatch
    if case .rotatingBatch(let batchSize, let reissueTriggerLifetimeLeft) = policy.options[1] {
      XCTAssertEqual(batchSize, 5)
      XCTAssertEqual(reissueTriggerLifetimeLeft, 655433)
    } else {
      XCTFail("Expected rotatingBatch policy at index 1")
    }

    // Third: PerRelyingParty
    if case .perRelyingParty(let batchSize, let reissueTriggerUnused, let reissueTriggerLifetimeLeft) = policy.options[2] {
      XCTAssertEqual(batchSize, 5)
      XCTAssertEqual(reissueTriggerUnused, 3)
      XCTAssertEqual(reissueTriggerLifetimeLeft, 655433)
    } else {
      XCTFail("Expected perRelyingParty policy at index 2")
    }
  }

  /// JSON has 2 options with 2 details each -> Should expand to 4 policies
  func testParsing_PID_SdJwtVc_ExpandsToFourPolicies() throws {
    let json = """
    {
      "format": "dc+sd-jwt",
      "scope": "PID_SdJwtVc",
      "vct": "eu.europa.ec.eudi.pid.1",
      "cryptographic_binding_methods_supported": ["jwk"],
      "credential_signing_alg_values_supported": ["ES256"],
      "proof_types_supported": {
        "jwt": {
          "proof_signing_alg_values_supported": ["ES256"]
        }
      },
      "credential_metadata": {
        "display": [{"name": "EU PID SD-JWT", "locale": "en-US"}],
        "credential_reuse_policy": {
          "id": "arf_annex_ii",
          "options": [
            {
              "details": ["limited_time", "rotating-batch"],
              "batch_size": 40,
              "reissue_trigger_lifetime_left": 655433
            },
            {
              "details": ["once_only", "per-relying-party"],
              "batch_size": 60,
              "reissue_trigger_unused": 10,
              "reissue_trigger_lifetime_left": 777543
            }
          ]
        }
      },
      "credential_definition": {
        "type": ["VerifiableCredential", "PersonIdentificationData"]
      }
    }
    """

    let data = json.data(using: .utf8)!
    let jsonObj = try JSON(data: data)
    let config = try SdJwtVcFormat.CredentialConfiguration(json: jsonObj)

    let policy = try XCTUnwrap(config.credentialReusePolicy)

    XCTAssertEqual(policy.options.count, 4)

    // From first JSON option (details: ["limited_time", "rotating-batch"])
    // Policy 0: LimitedTime
    if case .limitedTime(let reissueTriggerLifetimeLeft) = policy.options[0] {
      XCTAssertEqual(reissueTriggerLifetimeLeft, 655433)
    } else {
      XCTFail("Expected limitedTime policy at index 0")
    }

    // Policy 1: RotatingBatch
    if case .rotatingBatch(let batchSize, let reissueTriggerLifetimeLeft) = policy.options[1] {
      XCTAssertEqual(batchSize, 40)
      XCTAssertEqual(reissueTriggerLifetimeLeft, 655433)
    } else {
      XCTFail("Expected rotatingBatch policy at index 1")
    }

    // From second JSON option (details: ["once_only", "per-relying-party"])
    // Policy 2: OnceOnly
    if case .onceOnly(let batchSize, let reissueTriggerUnused) = policy.options[2] {
      XCTAssertEqual(batchSize, 60)
      XCTAssertEqual(reissueTriggerUnused, 10)
    } else {
      XCTFail("Expected onceOnly policy at index 2")
    }

    // Policy 3: PerRelyingParty
    if case .perRelyingParty(let batchSize, let reissueTriggerUnused, let reissueTriggerLifetimeLeft) = policy.options[3] {
      XCTAssertEqual(batchSize, 60)
      XCTAssertEqual(reissueTriggerUnused, 10)
      XCTAssertEqual(reissueTriggerLifetimeLeft, 777543)
    } else {
      XCTFail("Expected perRelyingParty policy at index 3")
    }
  }

  /// Test parsing unknown policy ID
  func testParsing_UnknownPolicyId_ReturnsNil() throws {
    let json = """
    {
      "id": "some_unknown_policy",
      "options": [{
        "details": ["once_only"],
        "batch_size": 10,
        "reissue_trigger_unused": 4
      }]
    }
    """

    let data = json.data(using: .utf8)!
    let policy = try JSONDecoder().decode(CredentialReusePolicy.self, from: data)

    // Policy is parsed but will be rejected by validator
    XCTAssertEqual(policy.id, "some_unknown_policy")
  }

  /// Test parsing with empty details array
  func testParsing_EmptyDetailsArray_ThrowsError() {
    let json = """
    {
      "id": "arf_annex_ii",
      "options": [{
        "details": [],
        "batch_size": 10,
        "reissue_trigger_unused": 4
      }]
    }
    """

    let data = json.data(using: .utf8)!

    XCTAssertThrowsError(
      try JSONDecoder().decode(CredentialReusePolicy.self, from: data)
    )
  }

  /// Test parsing with missing required field
  func testParsing_MissingRequiredField_ThrowsError() {
    let json = """
    {
      "id": "arf_annex_ii",
      "options": [{
        "details": ["once_only"],
        "batch_size": 10
      }]
    }
    """

    let data = json.data(using: .utf8)!

    // Missing reissue_trigger_unused for once_only
    XCTAssertThrowsError(
      try JSONDecoder().decode(CredentialReusePolicy.self, from: data)
    )
  }

  /// Test parsing with both once_only and limited_time (invalid)
  func testParsing_BothOnceOnlyAndLimitedTime_ThrowsError() {
    let json = """
    {
      "id": "arf_annex_ii",
      "options": [{
        "details": ["once_only", "limited_time"],
        "batch_size": 10,
        "reissue_trigger_unused": 4,
        "reissue_trigger_lifetime_left": 100
      }]
    }
    """

    let data = json.data(using: .utf8)!

    XCTAssertThrowsError(
      try JSONDecoder().decode(CredentialReusePolicy.self, from: data)
    )
  }

  /// Test parsing without base method (rotating-batch alone)
  func testParsing_RotatingBatchAlone_ThrowsError() {
    let json = """
    {
      "id": "arf_annex_ii",
      "options": [{
        "details": ["rotating-batch"],
        "batch_size": 10,
        "reissue_trigger_lifetime_left": 100
      }]
    }
    """

    let data = json.data(using: .utf8)!

    XCTAssertThrowsError(
      try JSONDecoder().decode(CredentialReusePolicy.self, from: data)
    )
  }

  /// Test that policies are in correct order (order matters for selection)
  func testParsing_MaintainsOrderFromJSON() throws {
    let json = """
    {
      "id": "arf_annex_ii",
      "options": [{
        "details": ["once_only", "limited_time"],
        "batch_size": 10,
        "reissue_trigger_unused": 4,
        "reissue_trigger_lifetime_left": 100
      }]
    }
    """

    // This should fail due to both once_only and limited_time
    let data = json.data(using: .utf8)!
    XCTAssertThrowsError(
      try JSONDecoder().decode(CredentialReusePolicy.self, from: data)
    )
  }

  // MARK: - Encoding Tests

  /// Test encoding policies back to JSON (each policy becomes separate option with single-element details)
  func testEncoding_ConvertsPoliciesBackToJSON() throws {
    let policy = CredentialReusePolicy(
      id: "arf_annex_ii",
      options: [
        .limitedTime(reissueTriggerLifetimeLeft: 885433),
        .onceOnly(batchSize: 10, reissueTriggerUnused: 4),
        .rotatingBatch(batchSize: 40, reissueTriggerLifetimeLeft: 655433),
        .perRelyingParty(batchSize: 60, reissueTriggerUnused: 10, reissueTriggerLifetimeLeft: 777543)
      ]
    )

    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let data = try encoder.encode(policy)
    let jsonString = String(data: data, encoding: .utf8)!

    // Verify structure
    XCTAssertTrue(jsonString.contains("\"id\" : \"arf_annex_ii\""))

    // Verify each policy is encoded as separate option with single-element details array
    XCTAssertTrue(jsonString.contains("\"details\" : [\n        \"limited_time\"\n      ]"))
    XCTAssertTrue(jsonString.contains("\"details\" : [\n        \"once_only\"\n      ]"))
    XCTAssertTrue(jsonString.contains("\"details\" : [\n        \"rotating-batch\"\n      ]"))
    XCTAssertTrue(jsonString.contains("\"details\" : [\n        \"per-relying-party\"\n      ]"))

    // Verify batch sizes are present
    XCTAssertTrue(jsonString.contains("\"batch_size\" : 10"))
    XCTAssertTrue(jsonString.contains("\"batch_size\" : 40"))
    XCTAssertTrue(jsonString.contains("\"batch_size\" : 60"))

    // Verify reissue triggers are present
    XCTAssertTrue(jsonString.contains("\"reissue_trigger_lifetime_left\" : 885433"))
    XCTAssertTrue(jsonString.contains("\"reissue_trigger_lifetime_left\" : 655433"))
    XCTAssertTrue(jsonString.contains("\"reissue_trigger_lifetime_left\" : 777543"))
    XCTAssertTrue(jsonString.contains("\"reissue_trigger_unused\" : 4"))
    XCTAssertTrue(jsonString.contains("\"reissue_trigger_unused\" : 10"))
  }

  /// Test round-trip encoding and decoding
  func testRoundTrip_EncodingAndDecoding() throws {
    let original = CredentialReusePolicy(
      id: "arf_annex_ii",
      options: [
        .limitedTime(reissueTriggerLifetimeLeft: 885433),
        .onceOnly(batchSize: 10, reissueTriggerUnused: 4)
      ]
    )

    // Encode
    let encoded = try JSONEncoder().encode(original)

    // Decode
    let decoded = try JSONDecoder().decode(CredentialReusePolicy.self, from: encoded)

    // Verify
    XCTAssertEqual(decoded.id, original.id)
    XCTAssertEqual(decoded.options.count, original.options.count)

    // Verify first policy
    if case .limitedTime(let reissueTriggerLifetimeLeft) = decoded.options[0] {
      XCTAssertEqual(reissueTriggerLifetimeLeft, 885433)
    } else {
      XCTFail("Expected limitedTime policy")
    }

    // Verify second policy
    if case .onceOnly(let batchSize, let reissueTriggerUnused) = decoded.options[1] {
      XCTAssertEqual(batchSize, 10)
      XCTAssertEqual(reissueTriggerUnused, 4)
    } else {
      XCTFail("Expected onceOnly policy")
    }
  }
}
