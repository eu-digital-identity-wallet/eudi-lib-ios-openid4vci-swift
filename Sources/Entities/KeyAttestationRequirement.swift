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
import SwiftyJSON

public enum KeyAttestationRequirementError: Error {
  case invalidConstraints
}

public enum KeyAttestationRequirement: Codable {
  
  case notRequired
  case requiredNoConstraints
  case required(
    keyStorageConstraints: [String],
    userAuthenticationConstraints: [String]
  )
  
  private enum CodingKeys: String, CodingKey {
    case keyStorageConstraints = "key_storage"
    case userAuthenticationConstraints = "user_authentication"
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    
    if let keyStorageConstraints = try? container.decode([String].self, forKey: .keyStorageConstraints),
       let userAuthenticationConstraints = try? container.decode([String].self, forKey: .userAuthenticationConstraints) {
      guard !keyStorageConstraints.isEmpty, !userAuthenticationConstraints.isEmpty else {
        throw KeyAttestationRequirementError.invalidConstraints
      }
      self = .required(
        keyStorageConstraints: keyStorageConstraints,
        userAuthenticationConstraints: userAuthenticationConstraints
      )
    } else {
      self = .notRequired
    }
  }
  
  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    
    switch self {
    case .notRequired, .requiredNoConstraints:
      break
    case .required(let keyStorageConstraints, let userAuthenticationConstraints):
      try container.encode(keyStorageConstraints, forKey: .keyStorageConstraints)
      try container.encode(userAuthenticationConstraints, forKey: .userAuthenticationConstraints)
    }
  }
}

public extension KeyAttestationRequirement {
  
  init(
    keyStorageConstraints: [String] = [],
    userAuthenticationConstraints: [String] = []
  ) throws {
    guard !keyStorageConstraints.isEmpty, !userAuthenticationConstraints.isEmpty else {
      throw KeyAttestationRequirementError.invalidConstraints
    }
    self = .required(
      keyStorageConstraints: keyStorageConstraints,
      userAuthenticationConstraints: userAuthenticationConstraints
    )
  }
  
  init(json: JSON?) throws {
    guard let json = json else {
      self = .notRequired
      return
    }
    
    let keyStorageConstraints = json[CodingKeys.keyStorageConstraints.rawValue].arrayValue.map { $0.stringValue }
    let userAuthenticationConstraints = json[CodingKeys.userAuthenticationConstraints.rawValue].arrayValue.map { $0.stringValue }
    
    if keyStorageConstraints.isEmpty || userAuthenticationConstraints.isEmpty {
      self = .notRequired
    } else {
      try self.init(
        keyStorageConstraints: keyStorageConstraints,
        userAuthenticationConstraints: userAuthenticationConstraints
      )
    }
  }
}
