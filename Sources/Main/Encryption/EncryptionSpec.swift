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
@preconcurrency import JOSESwift

public enum EncryptionSpecError: Swift.Error, LocalizedError, Equatable {
  case invalidKeyUse
  case missingAlgorithm
  case notAsymmetricAlgorithm
  case keyAndAlgorithmMismatch
  case cannotParseAlgorithm(String)
  case unsupportedKeyTypeForAsymmetricEncryption(String)
  
  public var errorDescription: String? {
    switch self {
    case .invalidKeyUse:
      return "Provided key use is not encryption"
    case .missingAlgorithm:
      return "Provided key does not contain an algorithm"
    case .notAsymmetricAlgorithm:
      return "Provided encryption algorithm is not an asymmetric encryption algorithm"
    case .keyAndAlgorithmMismatch:
      return "Encryption key and encryption algorithm do not match"
    case .cannotParseAlgorithm(let name):
      return "Cannot parse JWEAlgorithm from '\(name)'"
    case .unsupportedKeyTypeForAsymmetricEncryption(let name):
      return "Unsupported key type for asymmetric encryption '\(name)'"
    }
  }
}

/// Represents the specifications and parameters required for encryption.
public struct EncryptionSpec: Sendable {
  public let recipientKey: JWK
  public let encryptionMethod: JOSEEncryptionMethod
  public let compressionAlgorithm: CompressionAlgorithm?
  
  /// Derived from `recipientKey.algorithm`.
  public let algorithm: JWEAlgorithm

  /// Throws if the key/algorithm combination is invalid for asymmetric encryption.
  public init(
    recipientKey: JWK,
    encryptionMethod: JOSEEncryptionMethod,
    compressionAlgorithm: CompressionAlgorithm? = nil
  ) throws {
    self.recipientKey = recipientKey
    self.encryptionMethod = encryptionMethod
    self.compressionAlgorithm = compressionAlgorithm
    self.algorithm = try JWEAlgorithm.defaultFor(recipientKey: recipientKey)
  }
}

private extension JWEAlgorithm {
  /// Heuristic: pick a reasonable default based on JWK key type.
  static func defaultFor(
    recipientKey: JWK
  ) throws -> JWEAlgorithm {
    switch recipientKey.keyType.rawValue
      .uppercased() { // e.g., "EC", "RSA", "OKP", "oct"
    case "EC":
      // ECDH-ES family is the standard asymmetric *encryption* choice for EC keys.
      return .init(
        .ECDH_ES
      )
    case "RSA":
      // Prefer OAEP-256 these days; change to `.RSA_OAEP` if needed for interop.
      return .init(
        .RSA_OAEP_256
      )
    default:
      throw EncryptionSpecError
        .unsupportedKeyTypeForAsymmetricEncryption(
          recipientKey.keyType.rawValue
        )
    }
  }
}
