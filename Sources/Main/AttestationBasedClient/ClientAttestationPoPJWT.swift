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

public struct ClientAttestationPoPJWT {
  public let jws: JWS
  private let payload: JSON
  
  public init(jws: JWS) throws {
    self.jws = jws
    
    let payloadData = jws.payload.data()
    guard let jsonObject = try JSONSerialization.jsonObject(
      with: payloadData,
      options: []
    ) as? [String: Any] else {
      throw ClientAttestationError.invalidPayload
    }
    self.payload = JSON(jsonObject)
    
    guard payload[JWTClaimNames.issuer].string != nil else {
      throw ClientAttestationError.missingIssuerClaim
    }

    guard payload[JWTClaimNames.expirationTime].number != nil else {
      throw ClientAttestationError.missingExpirationClaim
    }
    
    guard payload[JWTClaimNames.jwtId].string != nil else {
      throw ClientAttestationError.missingExpirationClaim
    }
    
    guard payload[JWTClaimNames.audience].string != nil else {
      throw ClientAttestationError.missingExpirationClaim
    }
  }
}



