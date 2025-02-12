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
import JOSESwift

public enum Client {
  
  /// Represents a Public client
  case `public`(id: ClientId)
  
  /// Represents an Attested client
  case attested(attestationJWT: ClientAttestationJWT, popJwtSpec: ClientAttestationPoPJWTSpec)
  
  // Computed property for 'id' (common property for both cases)
  public var id: ClientId {
    switch self {
    case .public(let id):
      return id
    case .attested(let attestationJWT, _):
      return attestationJWT.clientId
    }
  }
  
  // MARK: - Validation
  public init(public id: ClientId) {
    self = .public(id: id)
  }
  
  public init(attestationJWT: ClientAttestationJWT, popJwtSpec: ClientAttestationPoPJWTSpec) throws {
    // Validate clientId
    let clientId = attestationJWT.clientId

    guard !clientId.isEmpty && !clientId.trimmingCharacters(in: .whitespaces).isEmpty else {
      throw ClientAttestationError.invalidClientId
    }
    
    // Validate public key
    guard (attestationJWT.pubKey?.isPublicKey ?? false) else {
      throw ClientAttestationError.missingJwkClaim
    }
    
    self = .attested(attestationJWT: attestationJWT, popJwtSpec: popJwtSpec)
  }
}

extension JWK {
  /// Determines if the JWK is a private key
  var isPrivateKey: Bool {
    switch self {
    case let rsaKey as RSAPrivateKey:
      return !rsaKey.privateExponent.isEmpty
    case let ecKey as ECPrivateKey:
      return !ecKey.privateKey.isEmpty
    default:
      return false
    }
  }
  
  /// Determines if the JWK is a public key
  var isPublicKey: Bool {
    return !isPrivateKey
  }
}

