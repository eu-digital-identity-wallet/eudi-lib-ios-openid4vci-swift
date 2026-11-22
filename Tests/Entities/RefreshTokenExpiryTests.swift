//
//  RefreshTokenExpiryTests.swift
//  OpenID4VCI
//
//  Created by Pankaj Sachdeva on 20.11.26.
//

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
