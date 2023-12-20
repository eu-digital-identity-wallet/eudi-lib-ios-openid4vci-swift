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

class CredentialIssuerIdTest: XCTestCase {
  
  override func setUp() async throws {
    try await super.setUp()
  }
  
  override func tearDown() {
    super.tearDown()
  }
  
  func testGivenInvalidSchemeWhenCredentialIssuerIdIsCreatedThenFail() throws {
    
    // Given
    let urlString = "ftp://issuer"
    
    // When
    do {
      _ = try CredentialIssuerId(urlString)
    } catch {
      
      // Then
      XCTAssertFalse(false, "Expected failure because scheme is not https")
      
      return
    }
    
    XCTExpectFailure("http for debugging purposes")
    XCTAssert(false)
  }
  
  func testGivenFragmentExistsWhenCredentialIssuerIdIsCreatedThenFail() throws {
    
    // Given
    let urlString = "https://issuer#fragment"
    
    // When
    do {
      _ = try CredentialIssuerId(urlString)
    } catch {
      
      // Then
      XCTAssertFalse(false, "Expected failure because url contains a fragment")
      
      return
    }
    
    XCTAssert(false)
  }
  
  func testGivenQueryExistsWhenCredentialIssuerIdIsCreatedThenFail() throws {
    
    // Given
    let urlString = "https://issuer?param1=true&param2=true"
    
    // When
    do {
      _ = try CredentialIssuerId(urlString)
    } catch {
      
      // Then
      XCTAssertFalse(false, "Expected failure because url conatins query items")
      
      return
    }
    
    XCTAssert(false)
  }
  
  func testGivenValidURLWhenCredentialIssuerIdIsCreatedThenSuccess() throws {
    
    // Given
    let urlString = "https://issuer"
    
    // When
    do {
      _ = try CredentialIssuerId(urlString)
    } catch {
      
      // Then
      XCTAssertFalse(true, "Invalid URL")
      
      return
    }
    
    XCTAssert(true, "Proper URL")
  }
}

