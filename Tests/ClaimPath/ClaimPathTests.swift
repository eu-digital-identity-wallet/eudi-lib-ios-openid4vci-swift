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
import SwiftyJSON
import Foundation

@testable import OpenID4VCI

final class ClaimPathTests: XCTestCase {
  
  func testInitialization() {
    let claimPath = ClaimPath([.claim(name: "name"), .arrayElement(index: 2)])
    XCTAssertEqual(claimPath.value.count, 2)
    XCTAssertEqual(claimPath.value[0], .claim(name: "name"))
    XCTAssertEqual(claimPath.value[1], .arrayElement(index: 2))
  }
  
  func testAppendingElements() {
    let path = ClaimPath([.claim(name: "user")])
    let newPath = path + .claim(name: "email")
    XCTAssertEqual(newPath.value, [.claim(name: "user"), .claim(name: "email")])
  }
  
  func testAppendingPaths() {
    let path1 = ClaimPath([.claim(name: "user")])
    let path2 = ClaimPath([.claim(name: "email")])
    let mergedPath = path1 + path2
    XCTAssertEqual(mergedPath.value, [.claim(name: "user"), .claim(name: "email")])
  }
  
  func testContains() {
    let fullPath = ClaimPath([.claim(name: "user"), .claim(name: "email")])
    let subPath = ClaimPath([.claim(name: "user")])
    XCTAssertTrue(fullPath.contains(subPath))
    XCTAssertFalse(subPath.contains(fullPath))
  }
  
  func testAllArrayElements() {
    let path = ClaimPath([.claim(name: "users")]).allArrayElements()
    XCTAssertEqual(path.value.last, .allArrayElements)
  }
  
  func testArrayElement() {
    let path = ClaimPath([.claim(name: "users")]).arrayElement(3)
    XCTAssertEqual(path.value.last, .arrayElement(index: 3))
  }
  
  func testClaim() {
    let path = ClaimPath([.claim(name: "user")]).claim("email")
    XCTAssertEqual(path.value.last, .claim(name: "email"))
  }
  
  func testParent() {
    let path = ClaimPath([.claim(name: "user"), .claim(name: "email")])
    let parent = path.parent()
    XCTAssertEqual(parent, ClaimPath([.claim(name: "user")]))
  }
  
  func testTail() {
    let path = ClaimPath([.claim(name: "user"), .claim(name: "email")])
    let tail = path.tail()
    XCTAssertEqual(tail, ClaimPath([.claim(name: "email")]))
  }
  
  func testEncodingDecoding() throws {
    let path = ClaimPath([.claim(name: "user"), .arrayElement(index: 2)])
    let encoded = try JSONEncoder().encode(path)
    let decoded = try JSONDecoder().decode(ClaimPath.self, from: encoded)
    XCTAssertEqual(decoded, path)
  }
  
  func testJSONDecoding() throws {
    let json = JSON(["user", 2])
    let path = try ClaimPath(json: json)
    XCTAssertEqual(path.value, [.claim(name: "user"), .arrayElement(index: 2)])
  }
  
  func testClaimPathElementContains() {
    XCTAssertTrue(ClaimPathElement.allArrayElements.contains(.arrayElement(index: 3)))
    XCTAssertTrue(ClaimPathElement.arrayElement(index: 3).contains(.arrayElement(index: 3)))
    XCTAssertFalse(ClaimPathElement.claim(name: "name").contains(.claim(name: "other")))
  }
  
  func testInvalidJSONDecoding() {
    let invalidJSON = JSON(true)
    XCTAssertThrowsError(try ClaimPath(json: invalidJSON))
  }
}

