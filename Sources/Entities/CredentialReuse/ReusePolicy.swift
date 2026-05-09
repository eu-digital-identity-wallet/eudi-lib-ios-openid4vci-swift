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

public enum ReusePolicy: Sendable, Equatable {
  case onceOnly(batchSize: Int, reissueTriggerUnused: Int)
  case limitedTime(reissueTriggerLifetimeLeft: Int)
  case rotatingBatch(batchSize: Int, reissueTriggerLifetimeLeft: Int)
  case perRelyingParty(
    batchSize: Int,
    reissueTriggerUnused: Int,
    reissueTriggerLifetimeLeft: Int
  )

  public var method: ReuseMethod {
    switch self {
    case .onceOnly: return .onceOnly
    case .limitedTime: return .limitedTime
    case .rotatingBatch: return .rotatingBatch
    case .perRelyingParty: return .perRelyingParty
    }
  }

  public var batchSize: Int? {
    switch self {
    case .onceOnly(let batchSize, _): return batchSize
    case .limitedTime: return nil
    case .rotatingBatch(let batchSize, _): return batchSize
    case .perRelyingParty(let batchSize, _, _): return batchSize
    }
  }

  public func validate() throws {
    switch self {
    case .onceOnly(let batchSize, let reissueTriggerUnused):
      guard batchSize > 0 else {
        throw CredentialReusePolicyError.missingRequiredField("batch_size must be > 0")
      }
      guard reissueTriggerUnused > 0 else {
        throw CredentialReusePolicyError.missingRequiredField("reissue_trigger_unused must be > 0")
      }
      guard reissueTriggerUnused < batchSize else {
        throw CredentialReusePolicyError.missingRequiredField("reissue_trigger_unused must be < batch_size")
      }

    case .limitedTime(let reissueTriggerLifetimeLeft):
      guard reissueTriggerLifetimeLeft > 0 else {
        throw CredentialReusePolicyError.missingRequiredField("reissue_trigger_lifetime_left must be > 0")
      }

    case .rotatingBatch(let batchSize, let reissueTriggerLifetimeLeft):
      guard batchSize > 0 else {
        throw CredentialReusePolicyError.missingRequiredField("batch_size must be > 0")
      }
      guard reissueTriggerLifetimeLeft > 0 else {
        throw CredentialReusePolicyError.missingRequiredField("reissue_trigger_lifetime_left must be > 0")
      }

    case .perRelyingParty(let batchSize, let reissueTriggerUnused, let reissueTriggerLifetimeLeft):
      guard batchSize > 0 else {
        throw CredentialReusePolicyError.missingRequiredField("batch_size must be > 0")
      }
      guard reissueTriggerUnused > 0 else {
        throw CredentialReusePolicyError.missingRequiredField("reissue_trigger_unused must be > 0")
      }
      guard reissueTriggerUnused < batchSize else {
        throw CredentialReusePolicyError.missingRequiredField("reissue_trigger_unused must be < batch_size")
      }
      guard reissueTriggerLifetimeLeft > 0 else {
        throw CredentialReusePolicyError.missingRequiredField("reissue_trigger_lifetime_left must be > 0")
      }
    }
  }

  /// Factory method to create policy options from details array
  public static func fromDetails(
    details: [ReuseMethod],
    batchSize: Int?,
    reissueTriggerUnused: Int?,
    reissueTriggerLifetimeLeft: Int?
  ) throws -> [ReusePolicy] {

    // Validate non-empty
    guard !details.isEmpty else {
      throw CredentialReusePolicyError.invalidDetailsCombination(details)
    }

    // Check for base method (once_only OR limited_time)
    let hasOnceOnly = details.contains(.onceOnly)
    let hasLimitedTime = details.contains(.limitedTime)

    guard hasOnceOnly || hasLimitedTime else {
      throw CredentialReusePolicyError.invalidPolicyStructure(
        "details must contain either once_only or limited_time"
      )
    }

    guard !(hasOnceOnly && hasLimitedTime) else {
      throw CredentialReusePolicyError.invalidPolicyStructure(
        "details cannot contain both once_only and limited_time"
      )
    }

    // Expand each detail into a separate ReusePolicy
    var policies: [ReusePolicy] = []

    for method in details {
      let policy: ReusePolicy

      switch method {
      case .onceOnly:
        guard let batchSize = batchSize else {
          throw CredentialReusePolicyError.missingRequiredField("batch_size required for once_only")
        }
        guard let reissueTriggerUnused = reissueTriggerUnused else {
          throw CredentialReusePolicyError.missingRequiredField("reissue_trigger_unused required for once_only")
        }
        policy = .onceOnly(batchSize: batchSize, reissueTriggerUnused: reissueTriggerUnused)

      case .limitedTime:
        guard let reissueTriggerLifetimeLeft = reissueTriggerLifetimeLeft else {
          throw CredentialReusePolicyError.missingRequiredField("reissue_trigger_lifetime_left required for limited_time")
        }
        policy = .limitedTime(reissueTriggerLifetimeLeft: reissueTriggerLifetimeLeft)

      case .rotatingBatch:
        guard let batchSize = batchSize else {
          throw CredentialReusePolicyError.missingRequiredField("batch_size required for rotating-batch")
        }
        guard let reissueTriggerLifetimeLeft = reissueTriggerLifetimeLeft else {
          throw CredentialReusePolicyError.missingRequiredField("reissue_trigger_lifetime_left required for rotating-batch")
        }
        policy = .rotatingBatch(batchSize: batchSize, reissueTriggerLifetimeLeft: reissueTriggerLifetimeLeft)

      case .perRelyingParty:
        guard let batchSize = batchSize else {
          throw CredentialReusePolicyError.missingRequiredField("batch_size required for per-relying-party")
        }
        guard let reissueTriggerUnused = reissueTriggerUnused else {
          throw CredentialReusePolicyError.missingRequiredField("reissue_trigger_unused required for per-relying-party")
        }
        guard let reissueTriggerLifetimeLeft = reissueTriggerLifetimeLeft else {
          throw CredentialReusePolicyError.missingRequiredField("reissue_trigger_lifetime_left required for per-relying-party")
        }
        policy = .perRelyingParty(
          batchSize: batchSize,
          reissueTriggerUnused: reissueTriggerUnused,
          reissueTriggerLifetimeLeft: reissueTriggerLifetimeLeft
        )
      }

      // Validate each policy
      try policy.validate()
      policies.append(policy)
    }

    return policies
  }
}
