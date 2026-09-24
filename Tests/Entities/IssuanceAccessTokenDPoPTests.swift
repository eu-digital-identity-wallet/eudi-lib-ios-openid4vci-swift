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

final class IssuanceAccessTokenDPoPTests: XCTestCase {

  // Servers are permitted by RFC 6749 §7.1 to return the token type in any case. The parser
  // must fold to the same TokenType regardless of the wire spelling.
  func testTokenTypeIsCaseInsensitive() {
    XCTAssertEqual(TokenType(value: "DPoP"), .dpop)
    XCTAssertEqual(TokenType(value: "dpop"), .dpop)
    XCTAssertEqual(TokenType(value: "DPOP"), .dpop)
    XCTAssertEqual(TokenType(value: "Bearer"), .bearer)
    XCTAssertEqual(TokenType(value: "bearer"), .bearer)
    XCTAssertEqual(TokenType(value: "BEARER"), .bearer)
  }

  // Nil / unknown token types default to Bearer, which is the safe fall-through for legacy
  // servers that don't set the field.
  func testUnknownTokenTypeFallsBackToBearer() {
    XCTAssertEqual(TokenType(value: nil), .bearer)
    XCTAssertEqual(TokenType(value: "mac"), .bearer)
  }

  // A DPoP-typed token with no constructor available must not be silently downgraded to a
  // Bearer header — sender-constraining would be lost with no signal to the caller.
  func testDPoPTokenWithoutConstructorThrows() async throws {
    let token = try IssuanceAccessToken(
      accessToken: "some-access-token",
      tokenType: .dpop
    )

    do {
      _ = try await token.dPoPOrBearerAuthorizationHeader(
        dpopConstructor: nil,
        dPopNonce: nil,
        endpoint: URL(string: "https://issuer.example.com/credentials")
      )
      XCTFail("Expected ValidationError.dpopConstructorMissing")
    } catch ValidationError.dpopConstructorMissing {
      XCTAssertTrue(true)
    } catch {
      XCTFail("Unexpected error: \(error)")
    }
  }

  // Same downgrade risk when the endpoint URL is missing but the token is DPoP-typed.
  func testDPoPTokenWithoutEndpointThrows() async throws {
    let token = try IssuanceAccessToken(
      accessToken: "some-access-token",
      tokenType: .dpop
    )

    do {
      _ = try await token.dPoPOrBearerAuthorizationHeader(
        dpopConstructor: nil,
        dPopNonce: nil,
        endpoint: nil
      )
      XCTFail("Expected ValidationError.dpopConstructorMissing")
    } catch ValidationError.dpopConstructorMissing {
      XCTAssertTrue(true)
    } catch {
      XCTFail("Unexpected error: \(error)")
    }
  }

  // Bearer tokens always produce a Bearer header regardless of DPoP plumbing.
  func testBearerTokenReturnsBearerHeader() async throws {
    let token = try IssuanceAccessToken(
      accessToken: "some-access-token",
      tokenType: .bearer
    )

    let headers = try await token.dPoPOrBearerAuthorizationHeader(
      dpopConstructor: nil,
      dPopNonce: nil,
      endpoint: URL(string: "https://issuer.example.com/credentials")
    )

    XCTAssertEqual(headers["Authorization"], "Bearer some-access-token")
    XCTAssertNil(headers["DPoP"])
  }
}
