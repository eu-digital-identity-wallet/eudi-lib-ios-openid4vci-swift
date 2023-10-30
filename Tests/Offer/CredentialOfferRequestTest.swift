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

class CredentialOfferRequestTest: XCTestCase {
  
  override func setUp() async throws {
    try await super.setUp()
  }
  
  override func tearDown() {
    super.tearDown()
  }
  
  func testInitializationWithValidURLByValue() throws {
    
    // Given
    let value = "value"
    let urlString = "https://example.com/?credential_offer=\(value)"
    
    // When
    let request = try CredentialOfferRequest(urlString: urlString)
    
    // Then
    switch request {
    case .passByValue(let metaData):
      XCTAssertEqual(metaData, value)
    default:
      XCTFail("Expected .passByValue, but got a different case.")
    }
  }
  
  func testInitializationWithValidURLByReference() throws {
    
    // Given
    let referenceUrlString = "https://reference.com"
    let urlString = "https://example.com/?credential_offer_uri=\(referenceUrlString)"
    
    // When
    let request = try CredentialOfferRequest(urlString: urlString)
    
    // Then
    switch request {
    case .fetchByReference(let url):
      XCTAssertEqual(url, URL(string: referenceUrlString))
    default:
      XCTFail("Expected .fetchByReference, but got a different case.")
    }
  }
  
  func testInitializationWithInvalidURL() {
    
    // Given
    let urlString = "invalid-url"
    
    // When
    XCTAssertThrowsError(try CredentialOfferRequest(urlString: urlString)) { error in
      
      // Then
      guard let error = error as? CredentialOfferRequestValidationError else {
        XCTAssert(false, "Unexpected error")
        return
      }
      switch error {
      case .oneOfCredentialOfferOrCredentialOfferUri:
        XCTAssertTrue(true)
      default:
        XCTAssert(false, "Unexpected error")
      }
    }
  }
  
  func testInitializationWithMissingParameters() {
    
    // Given
    let urlString = "https://example.com/"
    
    // When
    XCTAssertThrowsError(try CredentialOfferRequest(urlString: urlString)) { error in
      
      // Then
      XCTAssertTrue(error is CredentialOfferRequestValidationError)
    }
  }
  
  func testInitializationWithEmptyParameters() {
    let urlString = "https://example.com/?credential_offer=&credential_offer_uri="
    
    XCTAssertThrowsError(try CredentialOfferRequest(urlString: urlString)) { error in
      XCTAssertTrue(error is CredentialOfferRequestValidationError)
    }
  }
  
  func testPassByValueCredentialIssuerWithValidRequestObjectExpectation() throws {
    
    // Given
    let value = """
    {
       "credential_issuer": "https://credential-issuer.example.com",
       "credentials": [
          "UniversityDegree_JWT",
          {
             "format": "mso_mdoc",
             "doctype": "org.iso.18013.5.1.mDL"
          }
       ],
       "grants": {
          "authorization_code": {
             "issuer_state": "eyJhbGciOiJSU0Et...FYUaBy"
          },
          "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
             "pre-authorized_code": "adhjhdjajkdkhjhdj",
             "user_pin_required": true
          }
       }
    }
    """
    let urlString = "https://example.com/?credential_offer=\(value)"
    
    // When
    let request = try CredentialOfferRequest(urlString: urlString)
    
    // Then
    switch request {
    case .passByValue(let metaData):
      XCTAssertEqual(metaData, value)
      
      if let request = CredentialOfferRequestObject(jsonString: value) {
        XCTAssert(request.credentials.count == 2)
        XCTAssert(request.grants?.authorizationCode.issuerState == "eyJhbGciOiJSU0Et...FYUaBy")
        
      } else {
        XCTFail("Invalid pass by value object.")
      }
      
    default:
      XCTFail("Expected .passByValue, but got a different case.")
    }
  }
}
