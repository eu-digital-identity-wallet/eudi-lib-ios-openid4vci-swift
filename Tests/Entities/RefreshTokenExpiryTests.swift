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

final class RefreshTokenExpiryTests: XCTestCase {

  private func expiries(_ json: String) throws -> (refresh: Int?, authorization: Int?) {
    let response = try JSONDecoder().decode(AccessTokenRequestResponse.self, from: Data(json.utf8))
    guard case .success(_, _, _, let refresh, let authorization, _, _, _) = response else {
      XCTFail("Expected .success")
      return (nil, nil)
    }
    return (refresh, authorization)
  }

  func testAuthorizationExpiresInDecodesSeparatelyFromRefreshExpiresIn() throws {
    let json = #"{ "access_token": "at", "refresh_token": "rt", "authorization_expires_in": 2592000, "refresh_expires_in": 50 }"#
    let decoded = try expiries(json)
    XCTAssertEqual(decoded.authorization, 2_592_000)
    XCTAssertEqual(decoded.refresh, 50)
  }

  func testAuthorizationExpiresInAcceptsStringValue() throws {
    let json = #"{ "access_token": "at", "refresh_token": "rt", "authorization_expires_in": "100" }"#
    XCTAssertEqual(try expiries(json).authorization, 100)
  }

  func testMissingAuthorizationExpiresInLeavesRefreshExpiresInUnchanged() throws {
    let json = #"{ "access_token": "at", "refresh_token": "rt", "refresh_expires_in": 50 }"#
    let decoded = try expiries(json)
    XCTAssertNil(decoded.authorization)
    XCTAssertEqual(decoded.refresh, 50)
  }

  func testRefreshTokenRoundTripsAuthorizationExpiresIn() throws {
    let token = try IssuanceRefreshToken(refreshToken: "rt", expiresIn: 50, authorizationExpiresIn: 1000)
    let decoded = try JSONDecoder().decode(IssuanceRefreshToken.self, from: JSONEncoder().encode(token))

    XCTAssertEqual(decoded.refreshToken, "rt")
    XCTAssertEqual(decoded.expiresIn, 50)
    XCTAssertEqual(decoded.authorizationExpiresIn, 1000)
  }

  func testStoredRefreshTokenWithoutAuthorizationExpiresInStillDecodes() throws {
    let legacy = #"{ "refreshToken": "rt", "expiresIn": 1000 }"#
    let token = try JSONDecoder().decode(IssuanceRefreshToken.self, from: Data(legacy.utf8))

    XCTAssertEqual(token.refreshToken, "rt")
    XCTAssertEqual(token.expiresIn, 1000)
    XCTAssertNil(token.authorizationExpiresIn)
  }
}
