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

public struct KeyAttestationJWT: Sendable {
  
  public let jws: JWS
  public let attestedKeys: [JWK]
  
  public init(jwt: String) throws {
    
    self.jws = try .init(compactSerialization: jwt)
    try Self.validateHeader(jws.header)
    
    let payload = try Self.parsePayload(jws.payload)
    try Self.validateClaims(payload)
    
    self.attestedKeys = try Self.parseAttestedKeys(from: payload)
  }
  
  public init(jws: JWS) throws {
    
    self.jws = jws
    try Self.validateHeader(jws.header)
    
    let payload = try Self.parsePayload(jws.payload)
    try Self.validateClaims(payload)
    
    self.attestedKeys = try Self.parseAttestedKeys(from: payload)
  }
  
  // MARK: - Constants
  
  public static let keyAttestationJWTType = "keyattestation+jwt"
  
  // MARK: - Validation Helpers
  
  private static func validateHeader(_ header: JWSHeader) throws {
    guard ![.HS256, .HS384, .HS512].contains(header.algorithm) else {
      throw KeyAttestationError.invalidSignature
    }
    
    guard header.typ == keyAttestationJWTType else {
      throw KeyAttestationError.invalidType
    }
  }
  
  private static func parsePayload(_ payload: Payload) throws -> [String: Any] {
    
    let data = payload.data()
    
    guard
      let json = try? JSONSerialization.jsonObject(with: data, options: []),
      let dictionary = json as? [String: Any]
    else {
      throw KeyAttestationError.invalidPayload
    }
    return dictionary
  }
  
  private static func validateClaims(_ claims: [String: Any]) throws {
    guard claims["iat"] != nil else {
      throw KeyAttestationError.missingIAT
    }
    
    guard let keys = claims["attested_keys"] as? [[String: Any]], !keys.isEmpty else {
      throw KeyAttestationError.missingOrEmptyAttestedKeys
    }
  }
  
  private static func parseAttestedKeys(from claims: [String: Any]) throws -> [JWK] {
    guard let keys = claims["attested_keys"] as? [[String: Any]] else {
      throw KeyAttestationError.missingOrEmptyAttestedKeys
    }
    
    return try keys.enumerated().map { (index, jwkDict) in
      do {
        let data = try JSONSerialization.data(withJSONObject: jwkDict, options: [])
        let jwk = try JSONDecoder().decode(Either<ECPublicKey, RSAPublicKey>.self, from: data)
        
        switch jwk {
        case .left(let ec): return ec
        case .right(let rsa): return rsa
        }
      } catch {
        throw KeyAttestationError.invalidJWK(index: index, underlying: error)
      }
    }
  }
}


// MARK: - Errors

public enum KeyAttestationError: Error, LocalizedError {
  case invalidSignature
  case invalidType
  case invalidPayload
  case missingIAT
  case missingOrEmptyAttestedKeys
  case keyIsPrivate(index: Int)
  case invalidJWK(index: Int, underlying: Error)
  
  public var errorDescription: String? {
    switch self {
    case .invalidSignature:
      return "JWT must be signed with an asymmetric algorithm (not MAC)."
    case .invalidType:
      return "JWT 'typ' header must be '\(KeyAttestationJWT.keyAttestationJWTType)'."
    case .invalidPayload:
      return "JWT payload is not valid JSON."
    case .missingIAT:
      return "Missing 'iat' (issued at) claim."
    case .missingOrEmptyAttestedKeys:
      return "'attested_keys' claim is missing or empty."
    case .keyIsPrivate(let index):
      return "Key at index \(index) is a symmetric key; must be a public key."
    case .invalidJWK(let index, let error):
      return "Failed to parse JWK at index \(index): \(error.localizedDescription)"
    }
  }
}

