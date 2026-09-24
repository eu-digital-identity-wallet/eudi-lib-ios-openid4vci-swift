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

final class TokenResponseAndPostErrorTests: XCTestCase {

  private func decode(_ json: String) throws -> AccessTokenRequestResponse {
    try JSONDecoder().decode(AccessTokenRequestResponse.self, from: Data(json.utf8))
  }

  // RFC 6749 §4.2.2: `expires_in` is OPTIONAL and RECOMMENDED-integer. Servers frequently
  // send it as a JSON string. Must decode either shape without falling through.
  func testExpiresInAsStringDecodes() throws {
    let json = #"""
    {
      "access_token": "at-123",
      "token_type": "Bearer",
      "expires_in": "3600"
    }
    """#
    let response = try decode(json)
    guard case .success(_, let accessToken, _, _, let expiresIn, _, _) = response else {
      XCTFail("Expected .success, got \(response)")
      return
    }
    XCTAssertEqual(accessToken, "at-123")
    XCTAssertEqual(expiresIn, 3600)
  }

  // A token response without `expires_in` at all must still decode as success.
  func testExpiresInAbsentDecodes() throws {
    let json = #"""
    {
      "access_token": "at-123",
      "token_type": "Bearer"
    }
    """#
    let response = try decode(json)
    guard case .success(_, let accessToken, _, _, let expiresIn, _, _) = response else {
      XCTFail("Expected .success, got \(response)")
      return
    }
    XCTAssertEqual(accessToken, "at-123")
    XCTAssertEqual(expiresIn, 0)
  }

  // RFC 6749 §5.2: `error_description` is OPTIONAL. An error-only response must decode as
  // failure rather than DecodingError.dataCorrupted.
  func testFailureResponseWithoutDescriptionDecodes() throws {
    let json = #"""
    { "error": "invalid_grant" }
    """#
    let response = try decode(json)
    guard case .failure(let error, let description) = response else {
      XCTFail("Expected .failure, got \(response)")
      return
    }
    XCTAssertEqual(error, "invalid_grant")
    XCTAssertNil(description)
  }

  // The raw body must NEVER appear in PostError.cannotParse.errorDescription, otherwise
  // access_token / refresh_token leak into logs and crash reporters.
  func testCannotParseErrorDescriptionDoesNotIncludeRawBody() {
    let rawBody = #"{"access_token":"secret-at-DO-NOT-LEAK","refresh_token":"secret-rt-DO-NOT-LEAK"}"#
    let error = PostError.cannotParse(rawBody)

    let description = error.errorDescription ?? ""
    XCTAssertFalse(description.contains("secret-at-DO-NOT-LEAK"), "access_token leaked into error description")
    XCTAssertFalse(description.contains("secret-rt-DO-NOT-LEAK"), "refresh_token leaked into error description")
    XCTAssertFalse(description.contains("access_token"), "access_token key leaked into error description")
    XCTAssertFalse(description.contains("refresh_token"), "refresh_token key leaked into error description")
  }

  // The raw body is still preserved as the associated value so callers that pattern-match
  // (for example the JWE decrypt branch in IssuanceRequester) can still access it.
  func testCannotParsePreservesRawBodyAsAssociatedValue() {
    let rawBody = "opaque-jwe-payload"
    let error = PostError.cannotParse(rawBody)

    guard case .cannotParse(let recovered) = error else {
      XCTFail("Unexpected case")
      return
    }
    XCTAssertEqual(recovered, rawBody)
  }
}
