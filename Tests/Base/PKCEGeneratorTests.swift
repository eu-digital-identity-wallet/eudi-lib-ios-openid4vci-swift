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
  
  func testCodeVerifierHasRequestedLengthAndOnlyUnreservedCharacters() throws {
    let allowed = Set(PKCEGenerator.unreservedCharacters)
    for length in [43, 64, 128] {
      let verifier = try XCTUnwrap(PKCEGenerator.codeVerifier(length: length))
      XCTAssertEqual(verifier.count, length)
      XCTAssertTrue(verifier.allSatisfy(allowed.contains), "Unexpected character in \(verifier)")
    }
  }

  func testCodeVerifierRejectsLengthsOutsideRFC7636Range() {
    XCTAssertNil(PKCEGenerator.codeVerifier(length: 42))
    XCTAssertNil(PKCEGenerator.codeVerifier(length: 129))
  }

  func testRandomStringUsesTheWholeAlphabet() throws {
    // 66 characters; the old `byte % 66` mapping made the last 8 ("6"..."9", "-", ".", "_", "~")
    // less likely. 20,000 draws make missing any character vanishingly unlikely.
    XCTAssertEqual(PKCEGenerator.unreservedCharacters.count, 66)
    let sample = try XCTUnwrap(PKCEGenerator.generateRandomString(length: 20_000))
    XCTAssertEqual(Set(sample), Set(PKCEGenerator.unreservedCharacters))
  }

  func testGenerateRandomBase64StringDecodesToUnreservedCharacters() throws {
    let encoded = try XCTUnwrap(PKCEGenerator.generateRandomBase64String(length: 48))
    let decoded = try XCTUnwrap(Data(base64Encoded: encoded).flatMap { String(data: $0, encoding: .utf8) })
    XCTAssertEqual(decoded.count, 48)
    XCTAssertTrue(decoded.allSatisfy(Set(PKCEGenerator.unreservedCharacters).contains))
  }

  func testGenerateCodeChallenge() {
    if let codeChallenge = PKCEGenerator.generateCodeChallenge() {
      XCTAssertEqual(codeChallenge.count, 44) // Base64-encoded SHA256 hash length
    } else {
      XCTFail("Failed to generate code challenge")
    }
  }
}
