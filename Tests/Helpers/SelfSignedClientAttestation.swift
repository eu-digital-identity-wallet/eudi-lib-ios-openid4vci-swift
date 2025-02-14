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

@testable import OpenID4VCI

internal func selfSignedClient(
  clientId: String,
  algorithm: SignatureAlgorithm = .ES256,
  privateKey: SecKey
) throws -> Client {
  
  guard isECPrivateKey(privateKey) else {
    fatalError("Key shoulb be EC and private")
  }
  
  guard algorithm.isNotMacAlgorithm else {
    fatalError("MAC not supported")
  }
  
  let header: JWSHeader = .init(
    algorithm: algorithm
  )
  
  let duration: TimeInterval = 300
  let now = Date().timeIntervalSince1970
  let exp = Date().addingTimeInterval(duration).timeIntervalSince1970
  let payload: Payload = try! .init([
    "iss": clientId,
    "aud": clientId,
    "sub": clientId,
    "iat": now,
    "exp": exp,
    "cnf": [
      "jwk": ECPublicKey(
        publicKey: try! KeyController.generateECDHPublicKey(
          from: privateKey
        )
      ).toDictionary()
    ]
  ].toThrowingJSONData())
  
  let signer = Signer(
    signatureAlgorithm: algorithm,
    key: privateKey
  )!
  
  return try .attested(
    attestationJWT: .init(
      jws: .init(
        header: header,
        payload: payload,
        signer: signer
      )
    ),
    popJwtSpec: .init(
      signingAlgorithm: algorithm,
      duration: duration,
      typ: "oauth-client-attestation-pop+jwt",
      jwsSigner: signer
    )
  )
  
  func isECPrivateKey(_ secKey: SecKey) -> Bool {
    guard let attributes = SecKeyCopyAttributes(secKey) as? [CFString: Any] else {
      return false
    }
    
    let isPrivateKey = (attributes[kSecAttrKeyClass] as? String) == (kSecAttrKeyClassPrivate as String)
    let isECKey = (attributes[kSecAttrKeyType] as? String) == (kSecAttrKeyTypeEC as String)
    
    return isPrivateKey && isECKey
  }
}
