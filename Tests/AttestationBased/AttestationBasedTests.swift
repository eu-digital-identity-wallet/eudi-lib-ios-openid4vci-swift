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
import XCTest
import JOSESwift
import SwiftyJSON

@testable import OpenID4VCI

class AttestationBasedTests: XCTestCase {
  
  func testClientAttestation() async throws {
    
    let clientAttestation = try ClientAttestationJWT(
      jws: JWS(
        compactSerialization: TestsConstants.CNF_JWT
      )
    )
    
    let jwk = clientAttestation.pubKey
    XCTAssertNotNil(jwk)
  }
  
  func testClientAttestationPopJwt() async throws {
    
    let clientAttestation = try? ClientAttestationPoPJWT(
      jws: JWS(
        compactSerialization: TestsConstants.CNF_JWT
      )
    )
    
    XCTAssertNotNil(clientAttestation)
  }
  
  func testClient() async throws {
    
    let clientAttestationPop = try? ClientAttestationPoPJWT(
      jws: JWS(
        compactSerialization: TestsConstants.CNF_JWT
      )
    )

    XCTAssertNotNil(clientAttestationPop)
  }
  
  func testClientAttestationJWT() async throws {
    
    let client = try selfSignedClient(
      clientId: WALLET_DEV_CLIENT_ID,
      privateKey: try! KeyController.generateECDHPrivateKey()
    )
    
    XCTAssertNotNil(client)
  }

  func testClientAttestationWithValidAlgorithms_shouldSucceed() async throws {
    // Test that ES256, ES384, ES512 are all accepted
    let privateKey = try KeyController.generateECDHPrivateKey()

    // Test ES256
    let clientES256 = try selfSignedClient(
      clientId: "test-client-es256",
      algorithm: .ES256,
      privateKey: privateKey
    )
    XCTAssertNotNil(clientES256, "ES256 should be accepted")

    // Test ES384
    let clientES384 = try selfSignedClient(
      clientId: "test-client-es384",
      algorithm: .ES384,
      privateKey: privateKey
    )
    XCTAssertNotNil(clientES384, "ES384 should be accepted")

    // Test ES512
    let clientES512 = try selfSignedClient(
      clientId: "test-client-es512",
      algorithm: .ES512,
      privateKey: privateKey
    )
    XCTAssertNotNil(clientES512, "ES512 should be accepted")
  }

  func testClientAttestationWithInvalidAlgorithm_shouldFail() async throws {
    // Test that RS256 (RSA) is rejected
    // Create a JWT with RS256 algorithm in the header
    let now = Date().timeIntervalSince1970
    let exp = Date().addingTimeInterval(300).timeIntervalSince1970

    let headerDict: [String: Any] = [
      "alg": "RS256",
      "typ": "oauth-client-attestation+jwt"
    ]

    let payloadDict: [String: Any] = [
      "iss": "test-client",
      "aud": "test-client",
      "sub": "test-client",
      "iat": now,
      "exp": exp,
      "cnf": [
        "jwk": [
          "kty": "RSA",
          "n": "test",
          "e": "AQAB"
        ]
      ]
    ]

    let headerData = try JSONSerialization.data(withJSONObject: headerDict)
    let payloadData = try JSONSerialization.data(withJSONObject: payloadDict)

    let headerB64 = base64URLEncode(headerData)
    let payloadB64 = base64URLEncode(payloadData)
    let signature = "fake-signature"

    let compactJWT = "\(headerB64).\(payloadB64).\(signature)"
    let jws = try JWS(compactSerialization: compactJWT)

    // Should throw invalidAlgorithm error
    XCTAssertThrowsError(try ClientAttestationJWT(jws: jws)) { error in
      guard let attestationError = error as? ClientAttestationError,
            case .invalidAlgorithm(let allowed) = attestationError else {
        XCTFail("Expected ClientAttestationError.invalidAlgorithm, got \(error)")
        return
      }

      // Verify the error includes all allowed algorithms
      XCTAssertEqual(allowed.sorted(), ["ES256", "ES384", "ES512"])

      // Verify error message is descriptive
      let errorMessage = attestationError.errorDescription ?? ""
      XCTAssertTrue(errorMessage.contains("ES256"))
      XCTAssertTrue(errorMessage.contains("ES384"))
      XCTAssertTrue(errorMessage.contains("ES512"))
    }
  }

  func testClientAttestationWithHMACAlgorithm_shouldFail() async throws {
    // Test that HS256 (HMAC) is rejected
    let now = Date().timeIntervalSince1970
    let exp = Date().addingTimeInterval(300).timeIntervalSince1970

    let headerDict: [String: Any] = [
      "alg": "HS256",
      "typ": "oauth-client-attestation+jwt"
    ]

    let payloadDict: [String: Any] = [
      "iss": "test-client",
      "aud": "test-client",
      "sub": "test-client",
      "iat": now,
      "exp": exp,
      "cnf": [
        "jwk": [
          "kty": "oct",
          "k": "test"
        ]
      ]
    ]

    let headerData = try JSONSerialization.data(withJSONObject: headerDict)
    let payloadData = try JSONSerialization.data(withJSONObject: payloadDict)

    let headerB64 = base64URLEncode(headerData)
    let payloadB64 = base64URLEncode(payloadData)
    let signature = "fake-signature"

    let compactJWT = "\(headerB64).\(payloadB64).\(signature)"
    let jws = try JWS(compactSerialization: compactJWT)

    // Should throw invalidAlgorithm error
    XCTAssertThrowsError(try ClientAttestationJWT(jws: jws)) { error in
      guard let attestationError = error as? ClientAttestationError,
            case .invalidAlgorithm = attestationError else {
        XCTFail("Expected ClientAttestationError.invalidAlgorithm, got \(error)")
        return
      }
    }
  }

  // Helper function for base64 URL encoding
  private func base64URLEncode(_ data: Data) -> String {
    var base64String = data.base64EncodedString()
    base64String = base64String.replacingOccurrences(of: "/", with: "_")
    base64String = base64String.replacingOccurrences(of: "+", with: "-")
    base64String = base64String.replacingOccurrences(of: "=", with: "")
    return base64String
  }
}
