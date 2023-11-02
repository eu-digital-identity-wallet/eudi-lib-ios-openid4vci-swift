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

public class JOSEAlgorithm: Codable, Hashable {

  public static func == (lhs: JOSEAlgorithm, rhs: JOSEAlgorithm) -> Bool {
    lhs.name == rhs.name
  }

  public func hash(into hasher: inout Hasher) {
    hasher.combine(self.name)
    hasher.combine(self.requirement)
  }

  public let name: String
  public let requirement: Requirement

  init(name: String, requirement: Requirement) {
    self.name = name
    self.requirement = requirement
  }

  init(name: String) {
    self.name = name
    self.requirement = .OPTIONAL
  }

  public func toJsonData() throws -> Data {
    return try JSONSerialization.data(withJSONObject: [self.name])
  }
  
  required public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    name = try container.decode(String.self)
    requirement = .OPTIONAL
  }
}

public extension JOSEAlgorithm {
  enum Requirement: Codable, Hashable {
    case REQUIRED
    case RECOMMENDED
    case OPTIONAL
  }
}

