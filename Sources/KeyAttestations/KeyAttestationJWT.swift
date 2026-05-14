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
  
  public static let keyAttestationJWTType = "key-attestation+jwt"
  
  private static let allowedAlgorithms: Set<SignatureAlgorithm> = [.ES256, .ES384, .ES512]

  // MARK: - Validation Helpers
  
  private static func validateHeader(_ header: JWSHeader) throws {
    
    guard let algorithm = header.algorithm else {
      throw KeyAttestationError.missingAlgorithm
    }
    
    guard allowedAlgorithms.contains(algorithm) else {
      throw KeyAttestationError.unsupportedAlgorithm(
        found: algorithm,
        allowed: allowedAlgorithms
      )
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


  /// Validates that a JWT proof is signed by the first key in the attested_keys array.
  ///
  /// - The JWT proof must be signed by the first key (index 0) in attested_keys
  /// - The kid header in the JWT proof should be "0"
  /// - Signature verification must succeed using only the first attested key
  ///
  /// - Parameter jwtProof: The JWS object representing the JWT proof
  /// - Throws: `KeyAttestationError.jwtProofNotSignedByFirstAttestedKey` if verification fails
  public func validateJWTProofSignature(_ jwtProof: JWS) throws {
    guard let firstKey = attestedKeys.first else {
      throw KeyAttestationError.missingOrEmptyAttestedKeys
    }
    
    let verifier = try createVerifier(for: firstKey)
    _ = try jwtProof.validate(using: verifier)
  }

  /// Creates an appropriate verifier based on the key type.
  ///
  /// - Parameter key: The JWK to create a verifier for
  /// - Returns: A verifier that can validate signatures for this key type
  /// - Throws: `KeyAttestationError` if the key type is not supported
  private func createVerifier(for key: JWK) throws -> Verifier {
    let algorithm: SignatureAlgorithm

    switch key {
    case let ecKey as ECPublicKey:
      algorithm = switch ecKey.crv {
      case .P256: .ES256
      case .P384: .ES384
      case .P521: .ES512
      default:
        throw KeyAttestationError.unsupportedKeyType("Unsupported EC curve: \(ecKey.crv.rawValue)")
      }

    case let rsaKey as RSAPublicKey:
      // RSA keys not required by TS3 v1.5, but support for compatibility
      algorithm = .RS256

    default:
      let keyTypeDescription = type(of: key)
      throw KeyAttestationError.unsupportedKeyType(String(describing: keyTypeDescription))
    }
    
    guard let secKey = try JWKSecKeyConverter(jwk: key).secKey() else {
      throw KeyAttestationError.invalidKeyType
    }
    
    guard let verifier = Verifier(signatureAlgorithm: algorithm, key: secKey) else {
      throw KeyAttestationError.invalidKeyType
    }

    return verifier
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
  case missingAlgorithm
  case unsupportedAlgorithm(found: SignatureAlgorithm, allowed: Set<SignatureAlgorithm>)
  case jwtProofNotSignedByFirstAttestedKey
  case invalidKeyType
  case unsupportedKeyType(String)

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
    case .missingAlgorithm:
      return "Key attestation JWT header is missing the 'alg' parameter."
    case .unsupportedAlgorithm(let found, let allowed):
      let allowedNames = allowed.map { $0.rawValue }.sorted().joined(separator: ", ")
      return "Key attestation algorithm '\(found.rawValue)' is not supported, requires one of: \(allowedNames)."
    case .jwtProofNotSignedByFirstAttestedKey:
      return "JWT proof must be signed by the first key in the attested_keys array"
    case .invalidKeyType:
      return "Key type is invalid or cannot be used for signature verification."
    case .unsupportedKeyType(let keyType):
      return "Key type '\(keyType)' is not supported for signature verification."
    }
  }
}

