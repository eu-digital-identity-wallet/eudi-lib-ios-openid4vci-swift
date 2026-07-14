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
/// Construction eagerly validates that the JWT is a valid WIA
/// header `typ` is `oauth-client-attestation+jwt`, the signing algorithm is one of
/// ES256/ES384/ES512, and the claim set contains every required claim
/// (`iss`, `sub`, `exp`, `cnf.jwk`, `wallet_name`, `wallet_version`,
/// `wallet_solution_certification_information`, `client_status`).
public struct ClientAttestationJWT: Sendable {

  public let jws: JWS
  public let claimsSet: ClientAttestationJWTClaims

  public var header: JWSHeader { jws.header }
  public var clientId: ClientId { claimsSet.subject.value }
  public var cnf: ConfirmationClaim { claimsSet.confirmation }
  public var publicKey: JWK { claimsSet.confirmation.jwk }

  /// Backward-compatible accessor. Prefer `publicKey`.
  @available(*, deprecated, renamed: "publicKey")
  public var pubKey: JWK? { publicKey }

  private static let allowedAlgorithms: Set<SignatureAlgorithm> = [
    .ES256, .ES384, .ES512
  ]

  public init(jws: JWS) throws {
    guard let algorithm = jws.header.algorithm else {
      throw ClientAttestationError.notSigned
    }
    guard Self.allowedAlgorithms.contains(algorithm) else {
      throw ClientAttestationError.invalidAlgorithm(
        allowedAlgorithms: Self.allowedAlgorithms.map { $0.rawValue }
      )
    }

    if let typ = jws.header.typ, typ != AttestationBasedClientAuthenticationSpec.attestationJwtType {
      throw ClientAttestationError.invalidTypHeader(
        expected: AttestationBasedClientAuthenticationSpec.attestationJwtType,
        got: typ
      )
    }

    let payloadData = jws.payload.data()
    guard let jsonObject = try JSONSerialization.jsonObject(
      with: payloadData,
      options: []
    ) as? [String: Any] else {
      throw ClientAttestationError.invalidPayload
    }
    let payload = JSON(jsonObject)

    self.claimsSet = try ClientAttestationJWTClaims.parse(payload: payload)
    self.jws = jws
  }

  /// Convenience initializer accepting the compact-serialized JWT string.
  public init(jwt: String) throws {
    let jws = try JWS(compactSerialization: jwt)
    try self.init(jws: jws)
  }
}
