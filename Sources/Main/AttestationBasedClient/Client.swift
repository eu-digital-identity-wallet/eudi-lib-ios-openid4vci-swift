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

public typealias ClientAttestationProvider = @Sendable (URL) -> (
  attestationJWT: ClientAttestationJWT,
  signingKey: SigningKeyProxy
)

public enum Client: Sendable {
  
  /// Represents a Public client
  case `public`(
    id: ClientId,
    alg: JWSAlgorithm,
    jwk: JWK,
    signingKey: SigningKeyProxy
  )
  
  /// Represents an Attested client
  case attested(
    id: ClientId,
    alg: JWSAlgorithm,
    jwk: JWK,
    popJwtSpec: ClientAttestationPoPJWTSpec,
    clientAttestationProvider: ClientAttestationProvider
  )
  
  // Computed property for 'id' (common property for both cases)
  public var id: ClientId {
    switch self {
    case .public(let id, _, _, _):
      return id
    case .attested(let id, _, _, _, _):
      return id
    }
  }
  
  // Computed property for public key
  public var jwk: JWK {
    switch self {
    case .public(_, _, let jwk, _):
      return jwk
    case .attested(_, _, let jwk, _, _):
      return jwk
    }
  }
  
  // Computed property for JWS alg
  public var alg: JWSAlgorithm {
    switch self {
    case .public(_, let alg, _, _):
      return alg
    case .attested(_, let alg, _, _, _):
      return alg
    }
  }
  
  // Computed property for 'provider'
  public func provider() -> ClientAttestationProvider? {
    switch self {
    case .public:
      return nil
    case .attested(_, _, _, _, let provider):
      return provider
    }
  }
  
  // Computed property for 'provider'
  public func spec() -> ClientAttestationPoPJWTSpec? {
    switch self {
    case .public:
      return nil
    case .attested(_, _, _, let spec, _):
      return spec
    }
  }

  // Computed property for signingKey
  public func signingKey() -> SigningKeyProxy? {
    switch self {
    case .public(_, _, _, let signingKey):
      return signingKey
    case .attested:
      return nil
    }
  }
  
  public init(
    public id: ClientId,
    alg: JWSAlgorithm,
    jwk: JWK,
    signingKey: SigningKeyProxy
  ) {
    self = .public(
      id: id,
      alg: alg,
      jwk: jwk,
      signingKey: signingKey
    )
  }
  
  public init(
    id: ClientId,
    alg: JWSAlgorithm,
    jwk: JWK,
    popJwtSpec: ClientAttestationPoPJWTSpec,
    clientAttestationProvider: @escaping ClientAttestationProvider
  ) throws {
    self = .attested(
      id:id,
      alg: alg,
      jwk: jwk,
      popJwtSpec: popJwtSpec,
      clientAttestationProvider: clientAttestationProvider
    )
  }
  
  internal var attested: (id: ClientId, popJwtSpec: ClientAttestationPoPJWTSpec, clientAttestationProvider: ClientAttestationProvider)? {
    return switch self {
    case .public:
      nil
    case .attested(let id, _, _, let popJwtSpec, let clientAttestationProvider):
      (id, popJwtSpec, clientAttestationProvider)
    }
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
