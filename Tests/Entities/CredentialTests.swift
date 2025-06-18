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

final class CredentialTests: XCTestCase {
  
  func testDecodeStringCredential() throws {
    let jsonString = "\"string credential\""
    let data = jsonString.data(using: .utf8)!
    
    let credential = try JSONDecoder().decode(Credential.self, from: data)
    
    switch credential {
    case .string(let value):
      XCTAssertEqual(value, "string credential")
    default:
      XCTFail("Expected .string, got \(credential)")
    }
  }
  
  func testDecodeJsonCredential() throws {
    let jsonObject = ["name": "John", "age": 42] as [String: Any]
    let data = try JSONSerialization.data(withJSONObject: jsonObject)
    
    let credential = try JSONDecoder().decode(Credential.self, from: data)
    
    switch credential {
    case .json(let json):
      XCTAssertEqual(json["name"].stringValue, "John")
      XCTAssertEqual(json["age"].intValue, 42)
    default:
      XCTFail("Expected .json, got \(credential)")
    }
  }
  
  func testEncodeStringCredential() throws {
    let credential = Credential.string("encoded string")
    let data = try JSONEncoder().encode(credential)
    let decoded = String(data: data, encoding: .utf8)
    
    XCTAssertEqual(decoded, "\"encoded string\"")
  }
  
  func testEncodeJsonCredential() throws {
    let json = JSON(["name": "John"])
    let credential = Credential.json(json)
    
    let data = try JSONEncoder().encode(credential)
    let decodedJson = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
    
    XCTAssertEqual(decodedJson?["name"] as? String, "John")
  }
}
