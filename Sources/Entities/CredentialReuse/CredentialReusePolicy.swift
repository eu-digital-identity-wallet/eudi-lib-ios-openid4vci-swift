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

/// Controls how attestations should be re-used when presented to relying parties
public struct CredentialReusePolicy: Sendable, Equatable {

  public let id: String
  public let options: [ReusePolicy]

  public init(id: String, options: [ReusePolicy]) {
    self.id = id
    self.options = options
  }
}

extension CredentialReusePolicy: Codable {

  enum CodingKeys: String, CodingKey {
    case id
    case options
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)

    id = try container.decode(String.self, forKey: .id)


    let jsonOptions = try container.decode([ReusePolicyOption].self, forKey: .options)
    var expandedPolicies: [ReusePolicy] = []

    for jsonOption in jsonOptions {
      let policies = try ReusePolicy.fromDetails(
        details: jsonOption.details,
        batchSize: jsonOption.batchSize,
        reissueTriggerUnused: jsonOption.reissueTriggerUnused,
        reissueTriggerLifetimeLeft: jsonOption.reissueTriggerLifetimeLeft
      )
      expandedPolicies.append(contentsOf: policies)
    }

    guard !expandedPolicies.isEmpty else {
      throw CredentialReusePolicyError.invalidPolicyStructure("options array cannot be empty after expansion")
    }

    options = expandedPolicies
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(id, forKey: .id)

    // Convert each ReusePolicy to a ReusePolicyOption with single-element details array
    let jsonOptions = options.map { policy -> ReusePolicyOption in
      switch policy {
      case .onceOnly(let batchSize, let reissueTriggerUnused):
        return ReusePolicyOption(
          details: [.onceOnly],
          batchSize: batchSize,
          reissueTriggerUnused: reissueTriggerUnused,
          reissueTriggerLifetimeLeft: nil
        )

      case .limitedTime(let reissueTriggerLifetimeLeft):
        return ReusePolicyOption(
          details: [.limitedTime],
          batchSize: nil,
          reissueTriggerUnused: nil,
          reissueTriggerLifetimeLeft: reissueTriggerLifetimeLeft
        )

      case .rotatingBatch(let batchSize, let reissueTriggerLifetimeLeft):
        return ReusePolicyOption(
          details: [.rotatingBatch],
          batchSize: batchSize,
          reissueTriggerUnused: nil,
          reissueTriggerLifetimeLeft: reissueTriggerLifetimeLeft
        )

      case .perRelyingParty(let batchSize, let reissueTriggerUnused, let reissueTriggerLifetimeLeft):
        return ReusePolicyOption(
          details: [.perRelyingParty],
          batchSize: batchSize,
          reissueTriggerUnused: reissueTriggerUnused,
          reissueTriggerLifetimeLeft: reissueTriggerLifetimeLeft
        )
      }
    }

    try container.encode(jsonOptions, forKey: .options)
  }
}
