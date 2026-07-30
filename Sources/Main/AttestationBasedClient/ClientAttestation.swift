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
@preconcurrency import SwiftyJSON

/// A `ClientAttestationJWT` is the Wallet Instance Attestation (WIA) sent by the wallet
/// to the authorization server when using attestation-based client authentication.
///
public struct ClientAttestationJWT: Sendable, Equatable, Hashable {

  public let value: String

  public init(_ value: String) {
    self.value = value
  }

  /// Convenience initializer accepting an already-parsed `JWS`.
  public init(jws: JWS) {
    self.value = jws.compactSerializedString
  }
}

public extension ClientAttestationJWT {

  /// Decodes the JWT payload into the supplied claims type.
  ///
  /// Use this to opt in to a specific claims schema — for example
  /// `decodeClaimsSet(ClientAttestationJWTClaims.self)` to enforce the TS3 WIA shape.
  func decodeClaimsSet<T: Decodable>(_ type: T.Type) throws -> T {
    let payload = try decodePayloadData()
    return try JSONDecoder().decode(T.self, from: payload)
  }

  /// Decodes the JWT payload as a generic JSON structure.
  func decodeClaimsSet() throws -> JSON {
    let payload = try decodePayloadData()
    let jsonObject = try JSONSerialization.jsonObject(with: payload, options: [])
    return JSON(jsonObject)
  }

  /// Decodes the JWT payload into `ClientAttestationJWTClaims`, enforcing the TS3 WIA schema.
  func decodeAsClientAttestationClaims() throws -> ClientAttestationJWTClaims {
    try ClientAttestationJWTClaims.parse(payload: try decodeClaimsSet())
  }

  private func decodePayloadData() throws -> Data {
    let jws = try JWS(compactSerialization: value)
    return jws.payload.data()
  }
}
