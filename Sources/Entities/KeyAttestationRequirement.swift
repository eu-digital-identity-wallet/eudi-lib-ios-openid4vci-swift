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

/// Errors that can occur when initializing `KeyAttestationRequirement`.
public enum KeyAttestationRequirementError: Error {
  /// Indicates that the provided constraints are invalid.
  case invalidConstraints
}

/// Represents the requirements for key attestation.
public enum KeyAttestationRequirement: Codable, Sendable, Equatable {

  /// No key attestation required.
  case notRequired

  /// Key attestation is required, but no constraints are specified.
  case requiredNoConstraints

  /// Key attestation is required with specific constraints.
  ///
  /// - Parameters:
  ///   - keyStorageConstraints: Constraints related to key storage.
  ///   - userAuthenticationConstraints: Constraints related to user authentication.
  case required(
    keyStorageConstraints: [AttackPotentialResistance],
    userAuthenticationConstraints: [AttackPotentialResistance]
  )

  /// Coding keys for encoding and decoding.
  private enum CodingKeys: String, CodingKey {
    case keyStorageConstraints = "key_storage"
    case userAuthenticationConstraints = "user_authentication"
  }

  /// Initializes a `KeyAttestationRequirement` instance from a decoder.
  ///
  /// - Parameter decoder: The decoder to decode data from.
  /// - Throws: `KeyAttestationRequirementError.invalidConstraints` if constraints are invalid.
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)

    if let keyStorageConstraints = try? container.decode([AttackPotentialResistance].self, forKey: .keyStorageConstraints),
       let userAuthenticationConstraints = try? container.decode([AttackPotentialResistance].self, forKey: .userAuthenticationConstraints) {
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

  /// Encodes the `KeyAttestationRequirement` instance to an encoder.
  ///
  /// - Parameter encoder: The encoder to encode data into.
  /// - Throws: An error if encoding fails.
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

  /// Initializes a `KeyAttestationRequirement` instance with constraints.
  ///
  /// - Parameters:
  ///   - keyStorageConstraints: Constraints related to key storage.
  ///   - userAuthenticationConstraints: Constraints related to user authentication.
  /// - Throws: `KeyAttestationRequirementError.invalidConstraints` if constraints are empty.
  init(
    keyStorageConstraints: [AttackPotentialResistance] = [],
    userAuthenticationConstraints: [AttackPotentialResistance] = []
  ) throws {
    guard !keyStorageConstraints.isEmpty, !userAuthenticationConstraints.isEmpty else {
      throw KeyAttestationRequirementError.invalidConstraints
    }
    self = .required(
      keyStorageConstraints: keyStorageConstraints,
      userAuthenticationConstraints: userAuthenticationConstraints
    )
  }

  /// Initializes a `KeyAttestationRequirement` instance from a JSON object.
  ///
  /// - Parameter json: The JSON object to parse.
  /// - Throws: `KeyAttestationRequirementError.invalidConstraints` if constraints are invalid.
  init(json: JSON?) throws {
    guard let json = json else {
      self = .notRequired
      return
    }

    guard
      let keyStorageConstraints: [AttackPotentialResistance] = json[CodingKeys.keyStorageConstraints.rawValue].arrayObject?.compactMap({
        guard let potential = $0 as? String else { return nil }
        return AttackPotentialResistance(rawValue: potential)
      }),
      let userAuthenticationConstraints: [AttackPotentialResistance] = json[CodingKeys.userAuthenticationConstraints.rawValue].arrayObject?.compactMap({
        guard let potential = $0 as? String else { return nil }
        return AttackPotentialResistance(rawValue: potential)
      })
    else {
      self = .notRequired
      return
    }

    if keyStorageConstraints.isEmpty && userAuthenticationConstraints.isEmpty {
      self = .notRequired
      return
    }
    
    try self.init(
      keyStorageConstraints: keyStorageConstraints,
      userAuthenticationConstraints: userAuthenticationConstraints
    )
  }
}
