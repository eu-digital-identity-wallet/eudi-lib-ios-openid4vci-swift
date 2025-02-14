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

public struct ClientAttestationJWT {
  public let jws: JWS
  private let payload: JSON
  
  public init(jws: JWS) throws {
    self.jws = jws
    
    guard jws.header.algorithm != nil else {
      throw ClientAttestationError.notSigned
    }
    
    let payloadData = jws.payload.data()
    guard let jsonObject = try JSONSerialization.jsonObject(
      with: payloadData,
      options: []
    ) as? [String: Any] else {
      throw ClientAttestationError.invalidPayload
    }
    self.payload = JSON(jsonObject)
    
    guard let cnf = payload[JWTClaimNames.cnf].dictionary else {
      throw ClientAttestationError.missingCnfClaim
    }
    
    guard cnf[JWTClaimNames.JWK] != nil else {
      throw ClientAttestationError.missingJwkClaim
    }

    guard payload[JWTClaimNames.expirationTime].number != nil else {
      throw ClientAttestationError.missingExpirationClaim
    }
  }
  
  public var clientId: ClientId {
    return payload[JWTClaimNames.subject].string ?? ""
  }
  
  public var cnf: JSON {
    return JSON(payload[JWTClaimNames.cnf])
  }
  
  public var pubKey: JWK? {
    if let rsa = try? RSAPublicKey(data: cnf[JWTClaimNames.JWK].rawData()) {
      return rsa
    } else if let ec = try? ECPublicKey(data: cnf[JWTClaimNames.JWK].rawData()) {
      return ec
    }
    return nil
  }
}
