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
import XCTest
import SwiftyJSON
import JOSESwift

@testable import OpenID4VCI

final class JWKSecKeyConverterTests: XCTestCase {
  
  // MARK: - EC Key Tests
  
  func testECKeyConversion_validP256() throws {
    
    let converter = JWKSecKeyConverter(
      jwk: ECPublicKey(
        crv: .P256,
        x: "BZr1Rqvug_VlsYVuwUDiDfU_M0ZlzCHa9Hs8KSTRiIA",
        y: "L4chrslg9cj1kBynyZi7nZrYgPOJ7x0atRFdkxfXjtA"
      )
    )
    let secKey = try converter.secKey()
    
    XCTAssertNotNil(secKey, "Expected a valid SecKey for EC P-256 key")
  }
  
  // MARK: - RSA Key Tests
  
  func testRSAKeyConversion_validKey() throws {
    
    let converter = JWKSecKeyConverter(
      jwk: RSAPublicKey(
        modulus: "gRtjwICtIC_4ae33Ks7S80n32PLFEC4UtBanBFE9Pjzcpp4XWDPgbbOkNC9BZ-Jkyq6aoP_UknfJPI-cIvE6IE96bPNGs6DcfZ73Cq2A9ZXTdiuuOiqMwhEgLKFVRUZZ50calENLGyi96-6lcDnwLehh-kEg7ARITmrBO0iAjFU",
        exponent: "AQAB"
      )
    )
    let secKey = try converter.secKey()
    
    XCTAssertNotNil(secKey, "Expected a valid SecKey for RSA key")
  }
  
  func tests() async throws {
    
    let converter = JWKSecKeyConverter(
      jwk: TestsConstants.signedMetadataJWK
    )
    
    let secKey = try converter.secKey()!
    
    XCTAssertNotNil(secKey, "Expected a valid SecKey for EC P-256 key")
    
    let jws = try JWS(
      compactSerialization: TestsConstants.signedMetadata
    )
    
    let verifier: Verifier = .init(
      signatureAlgorithm: .ES256,
      key: secKey
    )!

    let validatedJws = try jws.validate(using: verifier)
    
    XCTAssertNotNil(validatedJws, "Expected a valid validated jws for EC P-256 key")
  }
}
