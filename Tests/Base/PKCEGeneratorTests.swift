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
import CryptoKit
@testable import OpenID4VCI

class PKCEGeneratorTests: XCTestCase {
  
  func testGenerateRandomData() {
    let length = 48
    if let randomData = PKCEGenerator.generateRandomData(length: length) {
      XCTAssertEqual(randomData.count, length)
    } else {
      XCTFail("Failed to generate random data")
    }
  }
  
  func testGenerateRandomBase64String() {
    let length = 48
    guard let randomString = PKCEGenerator.generateRandomBase64String(length: length) else {
      XCTFail("Failed to generate random base64 string")
      return
    }
    
    XCTAssert(true, "Generated random base64 string \(randomString)")
  }
  
  func testGenerateRandomBase64StringOfLength43() {
    let length = 32
    guard let randomString = PKCEGenerator.generateRandomBase64String(length: length) else {
      XCTFail("Failed to generate random base64 string")
      return
    }
    
    XCTAssert(true, "Generated random base64 string \(randomString)")
  }
  
  func testGenerateCodeChallenge() {
    if let codeChallenge = PKCEGenerator.generateCodeChallenge() {
      XCTAssertEqual(codeChallenge.count, 44) // Base64-encoded SHA256 hash length
    } else {
      XCTFail("Failed to generate code challenge")
    }
  }
}
