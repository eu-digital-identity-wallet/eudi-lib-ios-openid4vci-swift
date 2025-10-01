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
@preconcurrency import JOSESwift

public enum CredentialRequestEncryption: Decodable, Sendable {
  case notSupported
  case notRequired(
    jwks: [JWK],
    encryptionMethodsSupported: [JOSEEncryptionMethod],
    compressionMethodsSupported: [CompressionAlgorithm]?
  )
  case required(
    jwks: [JWK],
    encryptionMethodsSupported: [JOSEEncryptionMethod],
    compressionMethodsSupported: [CompressionAlgorithm]?
  )
  
  private enum CodingKeys: String, CodingKey {
    case encryptionRequired = "encryption_required"
    case jwks = "jwks"
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
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    
    let encryptionRequired = try? container.decode(Bool.self, forKey: .encryptionRequired)
    
    let jwkWrappers = try? container.decodeIfPresent(JWKSet.self, forKey: .jwks)
    let jwks: [JWK] = jwkWrappers?.keys.map { $0.key } ?? []
      
    let encryptionMethodsSupported = try? container.decode(
      [JOSEEncryptionMethod].self,
      forKey: .encryptionMethodsSupported
    )
    
    let compressionMethodsSupported = try? container.decode(
      [CompressionAlgorithm].self,
      forKey: .compressionMethodsSupported
    )
    
    let required = encryptionRequired ?? false
    if !required {
      guard
        !jwks.isEmpty,
        let encryptionMethodsSupported
      else {
        self = .notSupported
        return
      }
      
      self = .notRequired(
        jwks: jwks,
        encryptionMethodsSupported: encryptionMethodsSupported,
        compressionMethodsSupported: compressionMethodsSupported
      )
      
    } else {
      
      guard
        !jwks.isEmpty,
        let encryptionMethodsSupported
      else {
        throw ValidationError
          .error(
            reason: "No JWKS and encryption methods supported for required request encryption"
          )
      }
      self = .required(
        jwks: jwks,
        encryptionMethodsSupported: encryptionMethodsSupported,
        compressionMethodsSupported: compressionMethodsSupported
      )
    }
  }
}

package struct JWKSet: Decodable {
  package let keys: [AnyJWK]
}

package struct AnyJWK: Decodable {
  let key: JWK
  
  private enum KtyKeys: String, CodingKey {
    case kty
  }
  
  package init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: KtyKeys.self)
    let kty = try container.decode(String.self, forKey: .kty)
    
    switch kty {
    case "RSA":
      self.key = try RSAPublicKey(from: decoder)
    case "EC":
      self.key = try ECPublicKey(from: decoder)
    default:
      throw DecodingError.dataCorruptedError(
        forKey: KtyKeys.kty,
        in: container,
        debugDescription: "Unsupported JWK type: \(kty)"
      )
    }
  }
}
