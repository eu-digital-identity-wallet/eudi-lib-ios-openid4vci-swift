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

class ReusePolicyTests: XCTestCase {

  // MARK: - Individual Policy Creation Tests
  func testOnceOnly_IsValidWithBatchSizeAndReissueTriggerUnused() {
    let policy = ReusePolicy.onceOnly(batchSize: 10, reissueTriggerUnused: 4)

    if case .onceOnly(let batchSize, let reissueTriggerUnused) = policy {
      XCTAssertEqual(batchSize, 10)
      XCTAssertEqual(reissueTriggerUnused, 4)
      XCTAssertEqual(policy.batchSize, 10)
    } else {
      XCTFail("Expected onceOnly policy")
    }

    XCTAssertNoThrow(try policy.validate())
  }

  func testLimitedTime_IsValidWithReissueTriggerLifetimeLeft() {
    let policy = ReusePolicy.limitedTime(reissueTriggerLifetimeLeft: 885433)

    if case .limitedTime(let reissueTriggerLifetimeLeft) = policy {
      XCTAssertEqual(reissueTriggerLifetimeLeft, 885433)
      XCTAssertNil(policy.batchSize)
    } else {
      XCTFail("Expected limitedTime policy")
    }

    XCTAssertNoThrow(try policy.validate())
  }

  func testRotatingBatch_IsValid() {
    let policy = ReusePolicy.rotatingBatch(batchSize: 20, reissueTriggerLifetimeLeft: 100000)

    if case .rotatingBatch(let batchSize, let reissueTriggerLifetimeLeft) = policy {
      XCTAssertEqual(batchSize, 20)
      XCTAssertEqual(reissueTriggerLifetimeLeft, 100000)
      XCTAssertEqual(policy.batchSize, 20)
    } else {
      XCTFail("Expected rotatingBatch policy")
    }

    XCTAssertNoThrow(try policy.validate())
  }

  func testPerRelyingParty_IsValid() {
    let policy = ReusePolicy.perRelyingParty(
      batchSize: 5,
      reissueTriggerUnused: 3,
      reissueTriggerLifetimeLeft: 655433
    )

    if case .perRelyingParty(let batchSize, let reissueTriggerUnused, let reissueTriggerLifetimeLeft) = policy {
      XCTAssertEqual(batchSize, 5)
      XCTAssertEqual(reissueTriggerUnused, 3)
      XCTAssertEqual(reissueTriggerLifetimeLeft, 655433)
      XCTAssertEqual(policy.batchSize, 5)
    } else {
      XCTFail("Expected perRelyingParty policy")
    }

    XCTAssertNoThrow(try policy.validate())
  }

  // MARK: - fromDetails Expansion Tests

  func testFromDetails_FailsWhenDetailsIsEmpty() {
    XCTAssertThrowsError(
      try ReusePolicy.fromDetails(
        details: [],
        batchSize: nil,
        reissueTriggerUnused: nil,
        reissueTriggerLifetimeLeft: nil
      )
    )
  }

  func testFromDetails_FailsWhenRotatingBatchIsUsedWithoutBaseDetail() {
    XCTAssertThrowsError(
      try ReusePolicy.fromDetails(
        details: [.rotatingBatch],
        batchSize: 10,
        reissueTriggerUnused: nil,
        reissueTriggerLifetimeLeft: 100
      )
    )
  }

  func testFromDetails_FailsWhenPerRelyingPartyIsUsedWithoutBaseDetail() {
    XCTAssertThrowsError(
      try ReusePolicy.fromDetails(
        details: [.perRelyingParty],
        batchSize: 10,
        reissueTriggerUnused: 2,
        reissueTriggerLifetimeLeft: 100
      )
    )
  }

  func testFromDetails_FailsWhenDetailsContainsBothOnceOnlyAndLimitedTime() {
    XCTAssertThrowsError(
      try ReusePolicy.fromDetails(
        details: [.onceOnly, .limitedTime],
        batchSize: 10,
        reissueTriggerUnused: 2,
        reissueTriggerLifetimeLeft: 100
      )
    )
  }

  func testFromDetails_FailsWhenOnceOnlyIsMissingBatchSize() {
    XCTAssertThrowsError(
      try ReusePolicy.fromDetails(
        details: [.onceOnly],
        batchSize: nil,
        reissueTriggerUnused: 2,
        reissueTriggerLifetimeLeft: nil
      )
    )
  }

  func testFromDetails_FailsWhenOnceOnlyIsMissingReissueTriggerUnused() {
    XCTAssertThrowsError(
      try ReusePolicy.fromDetails(
        details: [.onceOnly],
        batchSize: 10,
        reissueTriggerUnused: nil,
        reissueTriggerLifetimeLeft: nil
      )
    )
  }

  func testFromDetails_FailsWhenReissueTriggerUnusedIsNotLowerThanBatchSize() {
    XCTAssertThrowsError(
      try ReusePolicy.fromDetails(
        details: [.onceOnly],
        batchSize: 10,
        reissueTriggerUnused: 10, // Should be < batchSize
        reissueTriggerLifetimeLeft: nil
      )
    )
  }

  func testFromDetails_FailsWhenLimitedTimeIsMissingReissueTriggerLifetimeLeft() {
    XCTAssertThrowsError(
      try ReusePolicy.fromDetails(
        details: [.limitedTime],
        batchSize: nil,
        reissueTriggerUnused: nil,
        reissueTriggerLifetimeLeft: nil
      )
    )
  }

  func testFromDetails_FailsWhenRotatingBatchIsMissingBatchSize() {
    XCTAssertThrowsError(
      try ReusePolicy.fromDetails(
        details: [.limitedTime, .rotatingBatch],
        batchSize: nil,
        reissueTriggerUnused: nil,
        reissueTriggerLifetimeLeft: 100
      )
    )
  }

  func testFromDetails_ReturnsOneOptionPerDetailEntry() throws {
    let policies = try ReusePolicy.fromDetails(
      details: [.limitedTime, .rotatingBatch, .perRelyingParty],
      batchSize: 5,
      reissueTriggerUnused: 3,
      reissueTriggerLifetimeLeft: 655433
    )

    XCTAssertEqual(policies.count, 3)

    // First: LimitedTime
    if case .limitedTime(let reissueTriggerLifetimeLeft) = policies[0] {
      XCTAssertEqual(reissueTriggerLifetimeLeft, 655433)
    } else {
      XCTFail("Expected limitedTime policy")
    }

    // Second: RotatingBatch
    if case .rotatingBatch(let batchSize, let reissueTriggerLifetimeLeft) = policies[1] {
      XCTAssertEqual(batchSize, 5)
      XCTAssertEqual(reissueTriggerLifetimeLeft, 655433)
    } else {
      XCTFail("Expected rotatingBatch policy")
    }

    // Third: PerRelyingParty
    if case .perRelyingParty(let batchSize, let reissueTriggerUnused, let reissueTriggerLifetimeLeft) = policies[2] {
      XCTAssertEqual(batchSize, 5)
      XCTAssertEqual(reissueTriggerUnused, 3)
      XCTAssertEqual(reissueTriggerLifetimeLeft, 655433)
    } else {
      XCTFail("Expected perRelyingParty policy")
    }
  }


  func testFromDetails_ReturnsOnceOnlyAndPerRelyingPartyOptions() throws {
    let policies = try ReusePolicy.fromDetails(
      details: [.onceOnly, .perRelyingParty],
      batchSize: 10,
      reissueTriggerUnused: 3,
      reissueTriggerLifetimeLeft: 200
    )

    
    XCTAssertEqual(policies.count, 2)

    // First: OnceOnly
    if case .onceOnly(let batchSize, let reissueTriggerUnused) = policies[0] {
      XCTAssertEqual(batchSize, 10)
      XCTAssertEqual(reissueTriggerUnused, 3)
    } else {
      XCTFail("Expected onceOnly policy")
    }

    // Second: PerRelyingParty
    if case .perRelyingParty(let batchSize, let reissueTriggerUnused, let reissueTriggerLifetimeLeft) = policies[1] {
      XCTAssertEqual(batchSize, 10)
      XCTAssertEqual(reissueTriggerUnused, 3)
      XCTAssertEqual(reissueTriggerLifetimeLeft, 200)
    } else {
      XCTFail("Expected perRelyingParty policy")
    }
  }

  // MARK: - Method Property Tests

  func testMethod_ReturnsCorrectReuseMethod() {
    XCTAssertEqual(ReusePolicy.onceOnly(batchSize: 10, reissueTriggerUnused: 4).method, .onceOnly)
    XCTAssertEqual(ReusePolicy.limitedTime(reissueTriggerLifetimeLeft: 100).method, .limitedTime)
    XCTAssertEqual(ReusePolicy.rotatingBatch(batchSize: 10, reissueTriggerLifetimeLeft: 100).method, .rotatingBatch)
    XCTAssertEqual(ReusePolicy.perRelyingParty(batchSize: 10, reissueTriggerUnused: 2, reissueTriggerLifetimeLeft: 100).method, .perRelyingParty)
  }

  // MARK: - Batch Size Tests

  func testBatchSize_ReturnsCorrectValue() {
    XCTAssertEqual(ReusePolicy.onceOnly(batchSize: 10, reissueTriggerUnused: 4).batchSize, 10)
    XCTAssertNil(ReusePolicy.limitedTime(reissueTriggerLifetimeLeft: 100).batchSize)
    XCTAssertEqual(ReusePolicy.rotatingBatch(batchSize: 20, reissueTriggerLifetimeLeft: 100).batchSize, 20)
    XCTAssertEqual(ReusePolicy.perRelyingParty(batchSize: 30, reissueTriggerUnused: 5, reissueTriggerLifetimeLeft: 100).batchSize, 30)
  }
}
