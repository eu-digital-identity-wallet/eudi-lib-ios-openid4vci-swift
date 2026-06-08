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
import SwiftyJSON

@testable import OpenID4VCI

final class KeyAttestationRequirementTests: XCTestCase {
  
  // MARK: - Initialization Tests
  
  func testInit_notRequired() {
    let requirement = KeyAttestationRequirement.notRequired
    XCTAssertEqual(requirement, .notRequired)
  }
  
  func testInit_requiredWithValidConstraints() throws {
    let keyStorageConstraints: [AttackPotentialResistance] = [
      .iso18045High,
      .iso18045EnhancedBasic
    ]
    
    let userAuthenticationConstraints: [AttackPotentialResistance] = [
      .iso18045Moderate
    ]
    
    let requirement = try KeyAttestationRequirement(
      keyStorageConstraints: keyStorageConstraints,
      userAuthenticationConstraints: userAuthenticationConstraints
    )
    
    if case let .required(storedConstraints, authConstraints, _) = requirement {
      XCTAssertEqual(storedConstraints, keyStorageConstraints)
      XCTAssertEqual(authConstraints, userAuthenticationConstraints)
    } else {
      XCTFail("Expected .required case")
    }
  }
  
  func testInit_requiredWithEmptyConstraints_throwsError() {
    XCTAssertThrowsError(try KeyAttestationRequirement(keyStorageConstraints: [], userAuthenticationConstraints: [])) { error in
      XCTAssertEqual(error as? KeyAttestationRequirementError, .invalidConstraints)
    }
  }
  
  // MARK: - Encoding & Decoding Tests
  
  func testEncoding_required() throws {
    let requirement = KeyAttestationRequirement.required(
      keyStorageConstraints: [.iso18045Basic],
      userAuthenticationConstraints: [.iso18045EnhancedBasic],
      preferredKeyStorageStatusPeriod: nil
    )
    
    let encoder = JSONEncoder()
    let data = try encoder.encode(requirement)
    let jsonString = String(data: data, encoding: .utf8)
    
    XCTAssertNotNil(jsonString)
    XCTAssertTrue(jsonString!.contains("\"key_storage\":[\"iso_18045_basic\"]"))
    XCTAssertTrue(jsonString!.contains("\"user_authentication\":[\"iso_18045_enhanced-basic\"]"))
  }
  
  func testDecoding_required() throws {
    let jsonData = """
        {
            "key_storage": ["iso_18045_high"],
            "user_authentication": ["iso_18045_enhanced-basic"]
        }
        """.data(using: .utf8)!
    
    let decoder = JSONDecoder()
    let requirement = try decoder.decode(KeyAttestationRequirement.self, from: jsonData)
    
    if case let .required(storedConstraints, authConstraints, _) = requirement {
      XCTAssertEqual(storedConstraints, [.iso18045High])
      XCTAssertEqual(authConstraints, [.iso18045EnhancedBasic])
    } else {
      XCTFail("Expected .required case")
    }
  }
  
  func testDecoding_notRequired() throws {
    let jsonData = "{}".data(using: .utf8)!
    let decoder = JSONDecoder()
    let requirement = try decoder.decode(KeyAttestationRequirement.self, from: jsonData)
    XCTAssertEqual(requirement, .notRequired)
  }
  
  func testDecoding_invalidConstraints_throwsError() {
    let jsonData = """
        {
            "key_storage": [],
            "user_authentication": []
        }
        """.data(using: .utf8)!
    
    let decoder = JSONDecoder()
    XCTAssertThrowsError(try decoder.decode(KeyAttestationRequirement.self, from: jsonData)) { error in
      XCTAssertEqual(error as? KeyAttestationRequirementError, .invalidConstraints)
    }
  }
  
  // MARK: - JSON Initialization Tests
  
  func testInitFromJSON_required() throws {
    let json: JSON = [
      "key_storage": [
        "iso_18045_basic"
      ],
      "user_authentication": [
        "iso_18045_high"
      ]
    ]
    
    let requirement = try KeyAttestationRequirement(json: json)
    
    if case let .required(storedConstraints, authConstraints, _) = requirement {
      XCTAssertEqual(storedConstraints, [.iso18045Basic])
      XCTAssertEqual(authConstraints, [.iso18045High])
    } else {
      XCTFail("Expected .required case")
    }
  }
  
  func testInitFromJSON_notRequired() throws {
    let json: JSON = JSON.null
    let requirement = try KeyAttestationRequirement(json: json)
    XCTAssertEqual(requirement, .notRequired)
  }
  
  func testInitFromJSON_invalidConstraints_returnsNotRequired() throws {
    let json: JSON = [
      "key_storage": [],
      "user_authentication": []
    ]

    let requirement = try KeyAttestationRequirement(json: json)
    XCTAssertEqual(requirement, .requiredNoConstraints)
  }

  // MARK: - Preferred Key Storage Status Period Tests

  func testDecoding_withPreferredKeyStorageStatusPeriod() throws {
    let jsonData = """
        {
            "key_storage": ["iso_18045_high"],
            "user_authentication": ["iso_18045_enhanced-basic"],
            "preferred_key_storage_status_period": 86400
        }
        """.data(using: .utf8)!

    let decoder = JSONDecoder()
    let requirement = try decoder.decode(KeyAttestationRequirement.self, from: jsonData)

    if case let .required(storedConstraints, authConstraints, preferredPeriod) = requirement {
      XCTAssertEqual(storedConstraints, [.iso18045High])
      XCTAssertEqual(authConstraints, [.iso18045EnhancedBasic])
      XCTAssertEqual(preferredPeriod, 86400)
    } else {
      XCTFail("Expected .required case")
    }
  }

  func testDecoding_withoutPreferredKeyStorageStatusPeriod() throws {
    let jsonData = """
        {
            "key_storage": ["iso_18045_high"],
            "user_authentication": ["iso_18045_enhanced-basic"]
        }
        """.data(using: .utf8)!

    let decoder = JSONDecoder()
    let requirement = try decoder.decode(KeyAttestationRequirement.self, from: jsonData)

    if case let .required(_, _, preferredPeriod) = requirement {
      XCTAssertNil(preferredPeriod)
    } else {
      XCTFail("Expected .required case")
    }
  }

  func testEncoding_withPreferredKeyStorageStatusPeriod() throws {
    let requirement = KeyAttestationRequirement.required(
      keyStorageConstraints: [.iso18045Basic],
      userAuthenticationConstraints: [.iso18045EnhancedBasic],
      preferredKeyStorageStatusPeriod: 3600
    )

    let encoder = JSONEncoder()
    let data = try encoder.encode(requirement)
    let jsonString = String(data: data, encoding: .utf8)

    XCTAssertNotNil(jsonString)
    XCTAssertTrue(jsonString!.contains("\"preferred_key_storage_status_period\":3600"))
  }

  func testInitFromJSON_withPreferredKeyStorageStatusPeriod() throws {
    let json: JSON = [
      "key_storage": [
        "iso_18045_basic"
      ],
      "user_authentication": [
        "iso_18045_high"
      ],
      "preferred_key_storage_status_period": 7200
    ]

    let requirement = try KeyAttestationRequirement(json: json)

    if case let .required(storedConstraints, authConstraints, preferredPeriod) = requirement {
      XCTAssertEqual(storedConstraints, [.iso18045Basic])
      XCTAssertEqual(authConstraints, [.iso18045High])
      XCTAssertEqual(preferredPeriod, 7200)
    } else {
      XCTFail("Expected .required case")
    }
  }

  func testInit_withPreferredKeyStorageStatusPeriod() throws {
    let requirement = try KeyAttestationRequirement(
      keyStorageConstraints: [.iso18045High],
      userAuthenticationConstraints: [.iso18045Moderate],
      preferredKeyStorageStatusPeriod: 43200
    )

    if case let .required(_, _, preferredPeriod) = requirement {
      XCTAssertEqual(preferredPeriod, 43200)
    } else {
      XCTFail("Expected .required case")
    }
  }

  // MARK: - ProofTypeSupportedMeta Integration Tests

  func testProofTypeSupportedMeta_withPreferredKeyStorageStatusPeriod() throws {
    let jsonData = """
        {
            "proof_signing_alg_values_supported": ["ES256", "ES384"],
            "key_attestations_required": {
                "key_storage": ["iso_18045_high"],
                "user_authentication": ["iso_18045_moderate"],
                "preferred_key_storage_status_period": 172800
            }
        }
        """.data(using: .utf8)!

    let decoder = JSONDecoder()
    let proofTypeMeta = try decoder.decode(ProofTypeSupportedMeta.self, from: jsonData)

    XCTAssertEqual(proofTypeMeta.algorithms, ["ES256", "ES384"])
    XCTAssertNotNil(proofTypeMeta.keyAttestationRequirement)

    if case let .required(_, _, preferredPeriod) = proofTypeMeta.keyAttestationRequirement {
      XCTAssertEqual(preferredPeriod, 172800)
    } else {
      XCTFail("Expected .required case with preferredKeyStorageStatusPeriod")
    }
  }

  func testProofTypesSupported_bothJwtAndAttestation() throws {
    // Test that both jwt and attestation proof types support preferred_key_storage_status_period
    let jsonData = """
        {
            "jwt": {
                "proof_signing_alg_values_supported": ["ES256"],
                "key_attestations_required": {
                    "key_storage": ["iso_18045_high"],
                    "user_authentication": ["iso_18045_moderate"],
                    "preferred_key_storage_status_period": 86400
                }
            },
            "attestation": {
                "proof_signing_alg_values_supported": ["ES256"],
                "key_attestations_required": {
                    "key_storage": ["iso_18045_enhanced-basic"],
                    "user_authentication": ["iso_18045_high"],
                    "preferred_key_storage_status_period": 172800
                }
            }
        }
        """.data(using: .utf8)!

    let decoder = JSONDecoder()
    let proofTypesSupported = try decoder.decode([String: ProofTypeSupportedMeta].self, from: jsonData)

    // Verify jwt proof type
    XCTAssertNotNil(proofTypesSupported["jwt"])
    if let jwtProofType = proofTypesSupported["jwt"],
       case let .required(_, _, jwtPreferredPeriod) = jwtProofType.keyAttestationRequirement {
      XCTAssertEqual(jwtPreferredPeriod, 86400)
    } else {
      XCTFail("Expected jwt proof type with preferred_key_storage_status_period")
    }

    // Verify attestation proof type
    XCTAssertNotNil(proofTypesSupported["attestation"])
    if let attestationProofType = proofTypesSupported["attestation"],
       case let .required(_, _, attestationPreferredPeriod) = attestationProofType.keyAttestationRequirement {
      XCTAssertEqual(attestationPreferredPeriod, 172800)
    } else {
      XCTFail("Expected attestation proof type with preferred_key_storage_status_period")
    }
  }
}
