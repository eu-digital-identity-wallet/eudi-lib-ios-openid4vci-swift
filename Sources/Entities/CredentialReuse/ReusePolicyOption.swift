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

/// JSON parsing intermediate structure for credential reuse policy options.
/// This struct is used ONLY for JSON encoding/decoding and is immediately
/// expanded into [ReusePolicy] via ReusePolicy.fromDetails().
///
struct ReusePolicyOption: Codable, Sendable, Equatable {
  let details: [ReuseMethod]
  let batchSize: Int?
  let reissueTriggerUnused: Int?
  let reissueTriggerLifetimeLeft: Int?

  enum CodingKeys: String, CodingKey {
    case details
    case batchSize = "batch_size"
    case reissueTriggerUnused = "reissue_trigger_unused"
    case reissueTriggerLifetimeLeft = "reissue_trigger_lifetime_left"
  }

  init(
    details: [ReuseMethod],
    batchSize: Int? = nil,
    reissueTriggerUnused: Int? = nil,
    reissueTriggerLifetimeLeft: Int? = nil
  ) {
    self.details = details
    self.batchSize = batchSize
    self.reissueTriggerUnused = reissueTriggerUnused
    self.reissueTriggerLifetimeLeft = reissueTriggerLifetimeLeft
  }
}
