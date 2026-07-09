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

    let jwt = try makeWIAJWT()
    let clientAttestation = try ClientAttestationJWT(
      jws: JWS(compactSerialization: jwt)
    )

    XCTAssertEqual(clientAttestation.clientId, "test-client")
    XCTAssertEqual(clientAttestation.claimsSet.walletName.value, "Test Wallet Solution")
    XCTAssertEqual(clientAttestation.claimsSet.walletVersion.value, "1.0.0")
    XCTAssertEqual(clientAttestation.claimsSet.clientStatus.status.statusList.index, 0)
    XCTAssertNotNil(clientAttestation.publicKey)
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
    
    let client = try attestedClient(
      clientId: WALLET_DEV_CLIENT_ID,
      privateKey: try! KeyController.generateECDHPrivateKey()
    )
    
    XCTAssertNotNil(client)
  }

  func testClientAttestationWithValidAlgorithms_shouldSucceed() async throws {
    // Test that ES256, ES384, ES512 are all accepted
    let privateKey = try KeyController.generateECDHPrivateKey()

    // Test ES256
    let clientES256 = try attestedClient(
      clientId: "test-client-es256",
      algorithm: .ES256,
      privateKey: privateKey
    )
    XCTAssertNotNil(clientES256, "ES256 should be accepted")

    // Test ES384
    let clientES384 = try attestedClient(
      clientId: "test-client-es384",
      algorithm: .ES384,
      privateKey: privateKey
    )
    XCTAssertNotNil(clientES384, "ES384 should be accepted")

    // Test ES512
    let clientES512 = try attestedClient(
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

  // MARK: - TS3 WIA validation tests

  func testWIA_missingWalletName_shouldFail() throws {
    let jwt = try makeWIAJWT { payload in
      payload.removeValue(forKey: "wallet_name")
    }
    XCTAssertThrowsError(try ClientAttestationJWT(jws: JWS(compactSerialization: jwt))) { error in
      guard case ClientAttestationError.missingWalletName = error else {
        XCTFail("Expected missingWalletName, got \(error)"); return
      }
    }
  }

  func testWIA_missingWalletVersion_shouldFail() throws {
    let jwt = try makeWIAJWT { payload in
      payload.removeValue(forKey: "wallet_version")
    }
    XCTAssertThrowsError(try ClientAttestationJWT(jws: JWS(compactSerialization: jwt))) { error in
      guard case ClientAttestationError.missingWalletVersion = error else {
        XCTFail("Expected missingWalletVersion, got \(error)"); return
      }
    }
  }

  func testWIA_missingWalletSolutionCertificationInformation_shouldFail() throws {
    let jwt = try makeWIAJWT { payload in
      payload.removeValue(forKey: "wallet_solution_certification_information")
    }
    XCTAssertThrowsError(try ClientAttestationJWT(jws: JWS(compactSerialization: jwt))) { error in
      guard case ClientAttestationError.missingWalletSolutionCertificationInformation = error else {
        XCTFail("Expected missingWalletSolutionCertificationInformation, got \(error)"); return
      }
    }
  }

  func testWIA_missingClientStatus_shouldFail() throws {
    let jwt = try makeWIAJWT { payload in
      payload.removeValue(forKey: "client_status")
    }
    XCTAssertThrowsError(try ClientAttestationJWT(jws: JWS(compactSerialization: jwt))) { error in
      guard case ClientAttestationError.missingClientStatus = error else {
        XCTFail("Expected missingClientStatus, got \(error)"); return
      }
    }
  }

  func testWIA_missingClientStatusExp_shouldFail() throws {
    let jwt = try makeWIAJWT { payload in
      var cs = payload["client_status"] as! [String: Any]
      cs.removeValue(forKey: "exp")
      payload["client_status"] = cs
    }
    XCTAssertThrowsError(try ClientAttestationJWT(jws: JWS(compactSerialization: jwt))) { error in
      guard case ClientAttestationError.invalidClientStatus = error else {
        XCTFail("Expected invalidClientStatus, got \(error)"); return
      }
    }
  }

  func testWIA_missingStatusList_shouldFail() throws {
    let jwt = try makeWIAJWT { payload in
      var cs = payload["client_status"] as! [String: Any]
      cs["status"] = [String: Any]()
      payload["client_status"] = cs
    }
    XCTAssertThrowsError(try ClientAttestationJWT(jws: JWS(compactSerialization: jwt))) { error in
      guard case ClientAttestationError.invalidStatusListReference = error else {
        XCTFail("Expected invalidStatusListReference, got \(error)"); return
      }
    }
  }

  func testWIA_blankWalletName_shouldFail() throws {
    let jwt = try makeWIAJWT { payload in
      payload["wallet_name"] = "   "
    }
    XCTAssertThrowsError(try ClientAttestationJWT(jws: JWS(compactSerialization: jwt))) { error in
      guard case ClientAttestationError.blankClaim(let name) = error, name == "wallet_name" else {
        XCTFail("Expected blankClaim(wallet_name), got \(error)"); return
      }
    }
  }

  func testWIA_wrongTypHeader_shouldFail() throws {
    let jwt = try makeWIAJWT(typHeader: "wrong+jwt")
    XCTAssertThrowsError(try ClientAttestationJWT(jws: JWS(compactSerialization: jwt))) { error in
      guard case ClientAttestationError.invalidTypHeader(let expected, let got) = error,
            expected == "oauth-client-attestation+jwt",
            got == "wrong+jwt" else {
        XCTFail("Expected invalidTypHeader, got \(error)"); return
      }
    }
  }

  func testWIA_missingIssuer_shouldFail() throws {
    let jwt = try makeWIAJWT { payload in
      payload.removeValue(forKey: "iss")
    }
    XCTAssertThrowsError(try ClientAttestationJWT(jws: JWS(compactSerialization: jwt))) { error in
      guard case ClientAttestationError.missingIssuerClaim = error else {
        XCTFail("Expected missingIssuerClaim, got \(error)"); return
      }
    }
  }

  func testWIA_missingSubject_shouldFail() throws {
    let jwt = try makeWIAJWT { payload in
      payload.removeValue(forKey: "sub")
    }
    XCTAssertThrowsError(try ClientAttestationJWT(jws: JWS(compactSerialization: jwt))) { error in
      guard case ClientAttestationError.missingSubject = error else {
        XCTFail("Expected missingSubject, got \(error)"); return
      }
    }
  }

  func testWIA_negativeStatusListIdx_shouldFail() throws {
    let jwt = try makeWIAJWT { payload in
      var cs = payload["client_status"] as! [String: Any]
      var status = cs["status"] as! [String: Any]
      var list = status["status_list"] as! [String: Any]
      list["idx"] = -1
      status["status_list"] = list
      cs["status"] = status
      payload["client_status"] = cs
    }
    XCTAssertThrowsError(try ClientAttestationJWT(jws: JWS(compactSerialization: jwt))) { error in
      guard case ClientAttestationError.invalidStatusListReference = error else {
        XCTFail("Expected invalidStatusListReference, got \(error)"); return
      }
    }
  }

  // MARK: - WIA builder

  private func makeWIAJWT(
    typHeader: String = "oauth-client-attestation+jwt",
    algorithm: SignatureAlgorithm = .ES256,
    mutate: ((inout [String: Any]) -> Void)? = nil
  ) throws -> String {

    let privateKey = try KeyController.generateECDHPrivateKey()
    let publicJwk = try ECPublicKey(
      publicKey: try KeyController.generateECDHPublicKey(from: privateKey)
    )

    let header = try JWSHeader(parameters: [
      "alg": algorithm.rawValue,
      "typ": typHeader
    ])

    let now = Date().timeIntervalSince1970
    let exp = Date().addingTimeInterval(300).timeIntervalSince1970
    var payload: [String: Any] = [
      "iss": "test-client",
      "aud": "test-client",
      "sub": "test-client",
      "iat": now,
      "exp": exp,
      "cnf": ["jwk": try publicJwk.toDictionary()],
      "wallet_name": "Test Wallet Solution",
      "wallet_version": "1.0.0",
      "wallet_solution_certification_information": [
        "certification_body": "Test CAB",
        "certification_number": "TEST-CERT-001"
      ],
      "client_status": [
        "status": [
          "status_list": [
            "idx": 0,
            "uri": "https://wallet-provider.example.org/status-lists/clients/1"
          ]
        ],
        "exp": Date().addingTimeInterval(7 * 24 * 3600).timeIntervalSince1970
      ]
    ]
    mutate?(&payload)

    let payloadData = try JSONSerialization.data(withJSONObject: payload, options: [])
    let signer = Signer(signatureAlgorithm: algorithm, key: privateKey)!
    let jws = try JWS(header: header, payload: Payload(payloadData), signer: signer)
    return jws.compactSerializedString
  }
}
