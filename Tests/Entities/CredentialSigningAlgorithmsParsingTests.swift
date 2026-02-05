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
import XCTest

@testable import OpenID4VCI

import XCTest
import SwiftyJSON

final class CredentialSigningAlgorithmsParsingTests: XCTestCase {
  
  func test_keepsStringValues() {
    let json = JSON([
      "credential_signing_alg_values_supported": ["ES256", "RS256"]
    ])
    
    let result = MsoMdocFormat.CredentialConfiguration.parseCredentialSigningAlgorithms(from: json)
    
    XCTAssertEqual(result, ["ES256", "RS256"])
  }
  
  func test_mapsSupportedCoseIntegers() {
    let json = JSON([
      "credential_signing_alg_values_supported": [-7, -35, -36]
    ])
    
    let result = MsoMdocFormat.CredentialConfiguration.parseCredentialSigningAlgorithms(from: json)
    
    XCTAssertEqual(result, ["ES256", "ES384", "ES512"])
  }
  
  func test_filtersUnsupportedIntegers() {
    let json = JSON([
      "credential_signing_alg_values_supported": [-999, 0, 12345]
    ])
    
    let result = MsoMdocFormat.CredentialConfiguration.parseCredentialSigningAlgorithms(from: json)
    
    XCTAssertEqual(result, [])
  }
  
  func test_mixedStringsAndIntegers_preservesOrderAndFiltersUnknowns() {
    let json = JSON([
      "credential_signing_alg_values_supported": ["RS256", -7, -999, "ES512", -35]
    ])
    
    let result = MsoMdocFormat.CredentialConfiguration.parseCredentialSigningAlgorithms(from: json)
    
    XCTAssertEqual(result, ["RS256", "ES256", "ES512", "ES384"])
  }
  
  func test_missingKey_returnsEmptyArray() {
    let json = JSON([:])
    
    let result = MsoMdocFormat.CredentialConfiguration.parseCredentialSigningAlgorithms(from: json)
    
    XCTAssertEqual(result, [])
  }
  
  func test_nonArrayValue_returnsEmptyArray() {
    let json = JSON([
      "credential_signing_alg_values_supported": "not-an-array"
    ])
    
    let result = MsoMdocFormat.CredentialConfiguration.parseCredentialSigningAlgorithms(from: json)
    
    XCTAssertEqual(result, [])
  }
}
