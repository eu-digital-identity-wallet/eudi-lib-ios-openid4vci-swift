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

final class HardenedSessionTests: XCTestCase {

  // MARK: - Session configuration

  // The default session must not persist URL cache to disk and must not accept persistent
  // cookies. Both are covered by URLSessionConfiguration.ephemeral. Regression guard: if
  // someone accidentally reverts to URLSession.shared, this test fails.
  func testDefaultSessionIsEphemeral() {
    let config = HardenedSession.default.configuration

    // Ephemeral configuration does not persist any of the following.
    XCTAssertTrue(
      config.urlCache == nil || config.urlCache?.diskCapacity == 0,
      "Default session must not persist URL cache to disk"
    )

    // Ephemeral configuration does not use HTTPCookieStorage.shared.
    XCTAssertNotEqual(
      config.httpCookieStorage,
      HTTPCookieStorage.shared,
      "Default session must not share cookie storage with the app"
    )
  }

  // The default session is NOT the process-wide URLSession.shared.
  func testDefaultSessionIsNotURLSessionShared() {
    XCTAssertNotEqual(HardenedSession.default, URLSession.shared)
  }

  // MARK: - Same-origin logic

  func testSameOriginAcceptsIdenticalURLs() {
    let a = URL(string: "https://issuer.example.com/credentials")!
    let b = URL(string: "https://issuer.example.com/credentials/deferred")!
    XCTAssertTrue(SameOriginRedirectDelegate.sameOrigin(a, b))
  }

  func testSameOriginRejectsDifferentHost() {
    let a = URL(string: "https://issuer.example.com/credentials")!
    let b = URL(string: "https://attacker.example.com/credentials")!
    XCTAssertFalse(SameOriginRedirectDelegate.sameOrigin(a, b))
  }

  func testSameOriginRejectsDifferentScheme() {
    let a = URL(string: "https://issuer.example.com/credentials")!
    let b = URL(string: "http://issuer.example.com/credentials")!
    XCTAssertFalse(SameOriginRedirectDelegate.sameOrigin(a, b))
  }

  func testSameOriginRejectsDifferentPort() {
    let a = URL(string: "https://issuer.example.com/credentials")!
    let b = URL(string: "https://issuer.example.com:8443/credentials")!
    XCTAssertFalse(SameOriginRedirectDelegate.sameOrigin(a, b))
  }

  // Default HTTPS port (443) and explicit :443 must be treated as the same origin.
  func testSameOriginTreatsDefaultPortAsExplicit() {
    let a = URL(string: "https://issuer.example.com/credentials")!
    let b = URL(string: "https://issuer.example.com:443/credentials")!
    XCTAssertTrue(SameOriginRedirectDelegate.sameOrigin(a, b))
  }

  func testSameOriginIsCaseInsensitiveOnSchemeAndHost() {
    let a = URL(string: "HTTPS://Issuer.Example.COM/credentials")!
    let b = URL(string: "https://issuer.example.com/credentials")!
    XCTAssertTrue(SameOriginRedirectDelegate.sameOrigin(a, b))
  }
}
