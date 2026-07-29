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

final class PolicyViolationTests: XCTestCase {

  // MARK: - PolicyViolation

  func testEquatable() {
    XCTAssertEqual(PolicyViolation("x"), PolicyViolation("x"))
    XCTAssertNotEqual(PolicyViolation("x"), PolicyViolation("y"))
  }

  func testPreservesValue() {
    XCTAssertEqual(PolicyViolation("boom").value, "boom")
  }

  // MARK: - Authorization

  func testGrantedWithNoWarningsIsCleanPass() {
    let outcome: Authorization = .granted()
    guard case .granted(let warnings) = outcome else {
      return XCTFail("Expected .granted")
    }
    XCTAssertTrue(warnings.isEmpty)
  }

  func testGrantedWithWarnings() {
    let warnings: [String: [PolicyViolation]] = [
      "cfg-1": [PolicyViolation("w1")],
      "global": [PolicyViolation("w2")]
    ]
    let outcome: Authorization = .granted(warnings: warnings)
    guard case .granted(let received) = outcome else {
      return XCTFail("Expected .granted")
    }
    XCTAssertEqual(received, warnings)
  }

  func testNotGrantedCarriesSingleError() {
    let outcome: Authorization = .notGranted(error: PolicyViolation("boom"))
    guard case .notGranted(let error) = outcome else {
      return XCTFail("Expected .notGranted")
    }
    XCTAssertEqual(error, PolicyViolation("boom"))
  }

  func testEquatableAuthorization() {
    let warnings: [String: [PolicyViolation]] = ["k": [PolicyViolation("w")]]
    XCTAssertEqual(
      Authorization.granted(warnings: warnings),
      Authorization.granted(warnings: warnings)
    )
    XCTAssertNotEqual(
      Authorization.granted(warnings: warnings),
      Authorization.notGranted(error: PolicyViolation("w"))
    )
  }
}
