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
@testable import OpenID4VCI

class URLModifierTests: XCTestCase {
  
  var resolver: AuthorizationServerMetadataResolver!
  
  override func setUp() async throws {
    resolver = AuthorizationServerMetadataResolver()
  }
  
  override func tearDown() async throws {
    resolver = nil
  }
  
  func testAppendPathComponents() async throws {
    if let url = URL(string: "https://keycloak.netcompany.com/realms/pid-issuer-realm") {
      let modifiedURL = await resolver.modifyURL(
        url: url,
        modificationType: .appendPathComponents(".well-known", "openid-configuration")
      )
      XCTAssertEqual(
        modifiedURL?.absoluteString,
        "https://keycloak.netcompany.com/realms/pid-issuer-realm/.well-known/openid-configuration"
      )
    } else {
      XCTFail("Failed to create URL")
    }
  }
  
  func testInsertPathComponents() async throws {
    if let url = URL(string: "https://keycloak.netcompany.com/realms/pid-issuer-realm") {
      let modifiedURL = await resolver.modifyURL(
        url: url,
        modificationType: .insertPathComponents(".well-known", "openid-configuration")
      )
      XCTAssertEqual(modifiedURL?.absoluteString, "https://keycloak.netcompany.com/.well-known/openid-configuration/realms/pid-issuer-realm")
    } else {
      XCTFail("Failed to create URL")
    }
  }
  
  func testAppendPathComponentsEmptyPath() async throws {
    if let url = URL(string: "https://keycloak.netcompany.com") {
      let modifiedURL = await resolver.modifyURL(
        url: url,
        modificationType: .appendPathComponents(".well-known", "openid-configuration")
      )
      XCTAssertEqual(modifiedURL?.absoluteString, "https://keycloak.netcompany.com/.well-known/openid-configuration")
    } else {
      XCTFail("Failed to create URL")
    }
  }
  
  func testInsertPathComponentsEmptyPath() async throws {
    if let url = URL(string: "https://keycloak.netcompany.com") {
      let modifiedURL = await resolver.modifyURL(
        url: url,
        modificationType: .insertPathComponents(".well-known", "openid-configuration")
      )
      XCTAssertEqual(modifiedURL?.absoluteString, "https://keycloak.netcompany.com/.well-known/openid-configuration")
    } else {
      XCTFail("Failed to create URL")
    }
  }
}

