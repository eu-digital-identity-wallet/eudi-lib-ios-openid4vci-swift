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
import SwiftyJSON

@testable import OpenID4VCI

class AuthorizationDetailTests: XCTestCase {
  
  func testAuthorizationTypeInit_ShouldSetTypeCorrectly() {
    let type = AuthorizationType(type: "testType")
    XCTAssertEqual(type.type, "testType")
  }
  
  func testAuthorizationTypeEncodeDecode_ShouldBeSymmetric() throws {
    let original = AuthorizationType(type: "vc_auth")
    let encoded = try JSONEncoder().encode(original)
    let decoded = try JSONDecoder().decode(AuthorizationType.self, from: encoded)
    XCTAssertEqual(decoded.type, original.type)
  }
  
  func testAuthorizationDetailInit_ShouldSetPropertiesCorrectly() {
    let type = AuthorizationType(type: "test_auth")
    let locations = ["https://test.com", "https://test.org"]
    let configId = "test-config"
    let detail = AuthorizationDetail(type: type, locations: locations, credentialConfigurationId: configId)
    
    XCTAssertEqual(detail.type.type, "test_auth")
    XCTAssertEqual(detail.locations, locations)
    XCTAssertEqual(detail.credentialConfigurationId, configId)
  }
  
  func testAuthorizationDetailEncodeDecode_ShouldBeSymmetric() throws {
    let type = AuthorizationType(type: "test_auth")
    let locations = ["https://issuer.test.com"]
    let configId = "test-config"
    
    let original = AuthorizationDetail(type: type, locations: locations, credentialConfigurationId: configId)
    let encoded = try JSONEncoder().encode(original)
    let decoded = try JSONDecoder().decode(AuthorizationDetail.self, from: encoded)
    
    XCTAssertEqual(decoded.type.type, type.type)
    XCTAssertEqual(decoded.locations, locations)
    XCTAssertEqual(decoded.credentialConfigurationId, configId)
  }
  
  func testAuthorizationDetailEncodeDecode_EmptyLocations() throws {
    let type = AuthorizationType(type: "vc_auth")
    let locations: [String] = []
    let configId = "emptyLocations"
    
    let original = AuthorizationDetail(type: type, locations: locations, credentialConfigurationId: configId)
    let encoded = try JSONEncoder().encode(original)
    let decoded = try JSONDecoder().decode(AuthorizationDetail.self, from: encoded)
    
    XCTAssertEqual(decoded.locations, [])
    XCTAssertEqual(decoded.credentialConfigurationId, configId)
  }
}
