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
    let keyStorageConstraints = ["SecureEnclave", "Hardware"]
    let userAuthenticationConstraints = ["Biometric", "PIN"]
    
    let requirement = try KeyAttestationRequirement(
      keyStorageConstraints: keyStorageConstraints,
      userAuthenticationConstraints: userAuthenticationConstraints
    )
    
    if case let .required(storedConstraints, authConstraints) = requirement {
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
      keyStorageConstraints: ["SecureEnclave"],
      userAuthenticationConstraints: ["Biometric"]
    )
    
    let encoder = JSONEncoder()
    let data = try encoder.encode(requirement)
    let jsonString = String(data: data, encoding: .utf8)
    
    XCTAssertNotNil(jsonString)
    XCTAssertTrue(jsonString!.contains("\"key_storage\":[\"SecureEnclave\"]"))
    XCTAssertTrue(jsonString!.contains("\"user_authentication\":[\"Biometric\"]"))
  }
  
  func testDecoding_required() throws {
    let jsonData = """
        {
            "key_storage": ["SecureEnclave"],
            "user_authentication": ["Biometric"]
        }
        """.data(using: .utf8)!
    
    let decoder = JSONDecoder()
    let requirement = try decoder.decode(KeyAttestationRequirement.self, from: jsonData)
    
    if case let .required(storedConstraints, authConstraints) = requirement {
      XCTAssertEqual(storedConstraints, ["SecureEnclave"])
      XCTAssertEqual(authConstraints, ["Biometric"])
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
      "key_storage": ["SecureEnclave"],
      "user_authentication": ["Biometric"]
    ]
    
    let requirement = try KeyAttestationRequirement(json: json)
    
    if case let .required(storedConstraints, authConstraints) = requirement {
      XCTAssertEqual(storedConstraints, ["SecureEnclave"])
      XCTAssertEqual(authConstraints, ["Biometric"])
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
    XCTAssertEqual(requirement, .notRequired)
  }
}
