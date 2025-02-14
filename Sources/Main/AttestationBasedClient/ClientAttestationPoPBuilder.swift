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
import SwiftyJSON

public protocol ClockType {
  func now() -> Date
}

public struct Clock: ClockType {
  public init() {}
  public func now() -> Date {
    return Date()
  }
}

public protocol ClientAttestationPoPBuilder {
  /// Builds a PoP JWT
  /// - Parameters:
  ///   - client: The `Attested` client for which to create the PoP JWT.
  ///   - clock: Wallet's clock.
  ///   - authServerId: The issuer claim of the OAUTH2/OIDC server.
  /// - Returns: A `ClientAttestationPoPJWT`.
  func buildAttestationPoPJWT(
    for client: Client,
    clock: ClockType,
    authServerId: URL
  ) throws -> ClientAttestationPoPJWT
}

public struct DefaultClientAttestationPoPBuilder: ClientAttestationPoPBuilder {
  public func buildAttestationPoPJWT(
    for client: Client,
    clock: ClockType,
    authServerId: URL
  ) throws -> ClientAttestationPoPJWT {
    switch client {
    case .attested(let attestationJWT, let popJwtSpec):
      let now = Date().timeIntervalSince1970
      let exp = Date().addingTimeInterval(popJwtSpec.duration).timeIntervalSince1970
      let jws: JWS = try .init(
        header: try .init(parameters: [
          JWTClaimNames.algorithm: popJwtSpec.signingAlgorithm.rawValue,
          JWTClaimNames.type: popJwtSpec.typ
        ]),
        payload: .init(JSON([
          JWTClaimNames.issuer: attestationJWT.clientId,
          JWTClaimNames.jwtId: String.randomBase64URLString(length: 20),
          JWTClaimNames.expirationTime: exp,
          JWTClaimNames.issuedAt: now,
          JWTClaimNames.audience: authServerId.absoluteString,
          JWTClaimNames.cnf: attestationJWT.cnf
        ]).rawData()),
        signer: popJwtSpec.jwsSigner
      )
      return try .init(jws: jws)
    default:
      throw ClientAttestationError.invalidClient
    }
  }
}

public extension DefaultClientAttestationPoPBuilder {
  /// Default builder instance
  static var `default`: ClientAttestationPoPBuilder {
    return DefaultClientAttestationPoPBuilder()
  }
}
