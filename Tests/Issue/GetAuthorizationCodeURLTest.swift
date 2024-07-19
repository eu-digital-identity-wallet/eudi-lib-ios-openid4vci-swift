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

class GetAuthorizationCodeURLTests: XCTestCase {
  
  func testValidURL() throws {
    let urlString = "https://example.com?client_id=123&request_uri=https://callback.com"
    let sut = try GetAuthorizationCodeURL(urlString: urlString)
    XCTAssertEqual(sut.url, URL(string: urlString))
  }
  
  func testInvalidURL() {
    XCTAssertThrowsError(try GetAuthorizationCodeURL(urlString: "invalid_url")) { error in
      XCTAssertTrue(error is ValidationError)
    }
  }
  
  func testNonHTTPSURL() {
    XCTAssertThrowsError(try GetAuthorizationCodeURL(urlString: "http://example.com?client_id=123")) { error in
      XCTAssertTrue(error is ValidationError)
    }
  }
  
  func testMissingQueryParameters() {
    XCTAssertThrowsError(try GetAuthorizationCodeURL(urlString: "https://example.com")) { error in
      XCTAssertTrue(error is AuthorizationCodeURLError)
    }
  }
  
  func testMissingClientIdParameter() {
    XCTAssertThrowsError(try GetAuthorizationCodeURL(urlString: "https://example.com?request_uri=https://callback.com")) { error in
      XCTAssertTrue(error is AuthorizationCodeURLError)
    }
  }
  
  func testMissingRequestUriParameter() {
    XCTAssertThrowsError(try GetAuthorizationCodeURL(urlString: "https://example.com?client=123")) { error in
      XCTAssertTrue(error is AuthorizationCodeURLError)
    }
  }
}

