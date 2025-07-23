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

final class CryptographicBindingMethodTests: XCTestCase {
  
  func testDecodeJwk() throws {
    let json = "\"jwk\"".data(using: .utf8)!
    let decoded = try JSONDecoder().decode(CryptographicBindingMethod.self, from: json)
    XCTAssertEqual(decoded, .jwk)
  }
  
  func testDecodeX5c() throws {
    let json = "\"x5c\"".data(using: .utf8)!
    let decoded = try JSONDecoder().decode(CryptographicBindingMethod.self, from: json)
    XCTAssertEqual(decoded, .x5c)
  }
  
  func testDecodeCoseKey() throws {
    let json = "\"cose_key\"".data(using: .utf8)!
    let decoded = try JSONDecoder().decode(CryptographicBindingMethod.self, from: json)
    XCTAssertEqual(decoded, .coseKey)
  }
  
  func testDecodeMso() throws {
    let json = "\"mso\"".data(using: .utf8)!
    let decoded = try JSONDecoder().decode(CryptographicBindingMethod.self, from: json)
    XCTAssertEqual(decoded, .mso)
  }
  
  func testDecodeDid() throws {
    let json = "\"did:key\"".data(using: .utf8)!
    let decoded = try JSONDecoder().decode(CryptographicBindingMethod.self, from: json)
    XCTAssertEqual(decoded, .did(method: "did:key"))
  }
  
  func testDecodeInvalidMethod() {
    let json = "\"invalid_method\"".data(using: .utf8)!
    XCTAssertThrowsError(try JSONDecoder().decode(CryptographicBindingMethod.self, from: json)) { error in
      XCTAssertTrue(error is ValidationError)
    }
  }
  
  func testEncodeJwk() throws {
    let method: CryptographicBindingMethod = .jwk
    let data = try JSONEncoder().encode(method)
    let encoded = String(data: data, encoding: .utf8)
    XCTAssertEqual(encoded, "\"jwk\"")
  }
  
  func testEncodeX5c() throws {
    let method: CryptographicBindingMethod = .x5c
    let data = try JSONEncoder().encode(method)
    let encoded = String(data: data, encoding: .utf8)
    XCTAssertEqual(encoded, "\"x5c\"")
  }
  
  func testEncodeCoseKey() throws {
    let method: CryptographicBindingMethod = .coseKey
    let data = try JSONEncoder().encode(method)
    let encoded = String(data: data, encoding: .utf8)
    XCTAssertEqual(encoded, "\"cose_key\"")
  }
  
  func testEncodeMso() throws {
    let method: CryptographicBindingMethod = .mso
    let data = try JSONEncoder().encode(method)
    let encoded = String(data: data, encoding: .utf8)
    XCTAssertEqual(encoded, "\"mso\"")
  }
  
  func testEncodeDid() throws {
    let method: CryptographicBindingMethod = .did(method: "did:web")
    let data = try JSONEncoder().encode(method)
    let encoded = String(data: data, encoding: .utf8)
    XCTAssertEqual(encoded, "\"did:web\"")
  }
  
  func testInitMethod() throws {
    XCTAssertEqual(try CryptographicBindingMethod(method: "jwk"), .jwk)
    XCTAssertEqual(try CryptographicBindingMethod(method: "x5c"), .x5c)
    XCTAssertEqual(try CryptographicBindingMethod(method: "cose_key"), .coseKey)
    XCTAssertEqual(try CryptographicBindingMethod(method: "mso"), .mso)
    XCTAssertEqual(try CryptographicBindingMethod(method: "did:example"), .did(method: "did:example"))
  }
  
  func testInitMethodInvalidCase() {
    XCTAssertThrowsError(try CryptographicBindingMethod(method: "invalid_method")) { error in
      XCTAssertTrue(error is ValidationError)
    }
  }
}
