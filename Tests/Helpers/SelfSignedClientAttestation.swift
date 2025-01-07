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

internal func selfSignedClient(privateKey: SecKey) throws -> Client {
  let algorithm: SignatureAlgorithm = .ES256
  let header: JWSHeader = .init(algorithm: algorithm)
  let payload: Payload = .init(Data())
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
      jwsSigner: signer
    )
  )
}
