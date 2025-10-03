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

public enum CredentialResponseEncryption: Decodable, Sendable {
  case notSupported
  case notRequired(
    algorithmsSupported: [JWEAlgorithm],
    encryptionMethodsSupported: [JOSEEncryptionMethod],
    compressionMethodsSupported: [CompressionAlgorithm]?
  )
  case required(
    algorithmsSupported: [JWEAlgorithm],
    encryptionMethodsSupported: [JOSEEncryptionMethod],
    compressionMethodsSupported: [CompressionAlgorithm]?
  )
  
  private enum CodingKeys: String, CodingKey {
    case encryptionRequired = "encryption_required"
    case algorithmsSupported = "alg_values_supported"
    case encryptionMethodsSupported = "enc_values_supported"
    case compressionMethodsSupported = "zip_values_supported"
  }
  
  var notSupported: Bool {
    switch self {
    case .notSupported:
      true
    default:
      false
    }
  }
  
  var required: Bool {
    switch self {
    case .required:
      true
    default:
      false
    }
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let encryptionRequired = try container.decode(Bool.self, forKey: .encryptionRequired)
    
    let algorithmsSupported = try? container.decode(
      [JWEAlgorithm].self,
      forKey: .algorithmsSupported
    )
    let encryptionMethodsSupported = try? container.decode(
      [JOSEEncryptionMethod].self,
      forKey: .encryptionMethodsSupported
    )
    
    let compressionMethodsSupported = try? container.decode(
      [CompressionAlgorithm].self,
      forKey: .compressionMethodsSupported
    )
    
    if !encryptionRequired {
      guard
        let algorithmsSupported,
        let encryptionMethodsSupported
      else {
        self = .notSupported
        return
      }
      
      self = .notRequired(
        algorithmsSupported: algorithmsSupported,
        encryptionMethodsSupported: encryptionMethodsSupported,
        compressionMethodsSupported: compressionMethodsSupported
      )
      
    } else {
      
      guard
        let algorithmsSupported,
        let encryptionMethodsSupported
      else {
        throw ValidationError
          .error(
            reason: "No algorithms and encryption methods supported"
          )
      }
      self = .required(
        algorithmsSupported: algorithmsSupported,
        encryptionMethodsSupported: encryptionMethodsSupported,
        compressionMethodsSupported: compressionMethodsSupported
      )
    }
  }
}
