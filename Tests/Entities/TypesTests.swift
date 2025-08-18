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

class TxCodeTests: XCTestCase {
  func testTxCodeDefaultsToNumericWhenMissing() throws {
    let json = """
    {
        "length": 4,
        "description": "Enter code"
    }
    """.data(using: .utf8)!
    
    let txCode = try JSONDecoder().decode(TxCode.self, from: json)
    
    XCTAssertEqual(txCode.inputMode, .numeric, "Missing input_mode should default to numeric")
    XCTAssertEqual(txCode.length, 4)
    XCTAssertEqual(txCode.description, "Enter code")
  }
  
  func testTxCodeParsesNumericExplicitly() throws {
    let json = """
    {
        "input_mode": "numeric",
        "length": 6,
        "description": "Enter numeric code"
    }
    """.data(using: .utf8)!
    
    let txCode = try JSONDecoder().decode(TxCode.self, from: json)
    
    XCTAssertEqual(txCode.inputMode, .numeric)
    XCTAssertEqual(txCode.length, 6)
  }
  
  func testTxCodeParsesTextExplicitly() throws {
    let json = """
    {
        "input_mode": "text",
        "length": 8,
        "description": "Enter text code"
    }
    """.data(using: .utf8)!
    
    let txCode = try JSONDecoder().decode(TxCode.self, from: json)
    
    XCTAssertEqual(txCode.inputMode, .text)
    XCTAssertEqual(txCode.length, 8)
  }
  
  func testTxCodeFailsOnInvalidInputMode() throws {
    let json = """
    {
        "input_mode": "invalid_mode",
        "length": 4,
        "description": "Invalid mode test"
    }
    """.data(using: .utf8)!
    
    XCTAssertThrowsError(
      try JSONDecoder().decode(TxCode.self, from: json),
      "Decoding should fail if input_mode has an unsupported value"
    ) { error in
      
      guard case DecodingError.dataCorrupted(let context) = error else {
        XCTFail("Expected dataCorrupted error, got \(error)")
        return
      }
      
      XCTAssertTrue(context.debugDescription.contains("TxCodeInputMode"))
    }
  }
}
