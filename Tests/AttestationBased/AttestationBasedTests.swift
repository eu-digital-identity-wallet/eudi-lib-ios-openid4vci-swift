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
    let clientAttestation = ClientAttestationJWT(jwt)

    XCTAssertEqual(clientAttestation.value, jwt)

    let claims = try clientAttestation.decodeAsClientAttestationClaims()
    XCTAssertEqual(claims.subject.value, "test-client")
    XCTAssertEqual(claims.walletName.value, "Test Wallet Solution")
    XCTAssertEqual(claims.walletVersion.value, "1.0.0")
    XCTAssertEqual(claims.clientStatus.status.statusList.index, 0)
    XCTAssertNotNil(claims.confirmation.jwk)
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

  func testPublicClient_carriesNoAttestationMaterial() async throws {

    let client = Client(public: "test-public-client")

    XCTAssertEqual(client.id, "test-public-client")
    XCTAssertNil(client.jwk)
    XCTAssertNil(client.alg)
    XCTAssertNil(client.provider())
    XCTAssertNil(client.spec())
    XCTAssertNil(client.attested)
  }

  func testPublicClient_popBuilderThrowsInvalidClient() async throws {

    let builder = DefaultClientAttestationPoPBuilder()

    do {
      _ = try await builder.buildAttestationPoPJWT(
        for: Client(public: "test-public-client"),
        algorithm: .ES256,
        clock: Clock(),
        authServerId: URL(string: "https://as.example.com")!,
        challenge: nil
      )
      XCTFail("Expected ClientAttestationError.invalidClient")
    } catch let error as ClientAttestationError {
      guard case .invalidClient = error else {
        return XCTFail("Expected ClientAttestationError.invalidClient, got \(error)")
      }
    }
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

  func testClientAttestation_constructionIsRelaxed() async throws {
    // Callers that need TS3 validation must opt in via `decodeAsClientAttestationClaims()`.
    let now = Date().timeIntervalSince1970
    let exp = Date().addingTimeInterval(300).timeIntervalSince1970

    let headerDict: [String: Any] = [
      "alg": "RS256",
      "typ": "wrong+jwt"
    ]

    let payloadDict: [String: Any] = [
      "iss": "test-client",
      "sub": "test-client",
      "iat": now,
      "exp": exp
    ]

    let headerData = try JSONSerialization.data(withJSONObject: headerDict)
    let payloadData = try JSONSerialization.data(withJSONObject: payloadDict)

    let compactJWT = "\(base64URLEncode(headerData)).\(base64URLEncode(payloadData)).fake-signature"

    // Construction succeeds — no parsing, no algorithm, no typ, no claims validation.
    let attestation = ClientAttestationJWT(compactJWT)
    XCTAssertEqual(attestation.value, compactJWT)

    // Opt-in validation still surfaces TS3 issues.
    XCTAssertThrowsError(try attestation.decodeAsClientAttestationClaims())
  }

  // Helper function for base64 URL encoding
  private func base64URLEncode(_ data: Data) -> String {
    var base64String = data.base64EncodedString()
    base64String = base64String.replacingOccurrences(of: "/", with: "_")
    base64String = base64String.replacingOccurrences(of: "+", with: "-")
    base64String = base64String.replacingOccurrences(of: "=", with: "")
    return base64String
  }

  // MARK: - TS3 WIA opt-in validation tests

  private func attestation(_ jwt: String) -> ClientAttestationJWT {
    ClientAttestationJWT(jwt)
  }

  func testWIA_missingWalletName_shouldFail() throws {
    let jwt = try makeWIAJWT { payload in
      payload.removeValue(forKey: "wallet_name")
    }
    XCTAssertThrowsError(try attestation(jwt).decodeAsClientAttestationClaims()) { error in
      guard case ClientAttestationError.missingWalletName = error else {
        XCTFail("Expected missingWalletName, got \(error)"); return
      }
    }
  }

  func testWIA_missingWalletVersion_shouldFail() throws {
    let jwt = try makeWIAJWT { payload in
      payload.removeValue(forKey: "wallet_version")
    }
    XCTAssertThrowsError(try attestation(jwt).decodeAsClientAttestationClaims()) { error in
      guard case ClientAttestationError.missingWalletVersion = error else {
        XCTFail("Expected missingWalletVersion, got \(error)"); return
      }
    }
  }

  func testWIA_missingWalletSolutionCertificationInformation_shouldFail() throws {
    let jwt = try makeWIAJWT { payload in
      payload.removeValue(forKey: "wallet_solution_certification_information")
    }
    XCTAssertThrowsError(try attestation(jwt).decodeAsClientAttestationClaims()) { error in
      guard case ClientAttestationError.missingWalletSolutionCertificationInformation = error else {
        XCTFail("Expected missingWalletSolutionCertificationInformation, got \(error)"); return
      }
    }
  }

  func testWIA_missingClientStatus_shouldFail() throws {
    let jwt = try makeWIAJWT { payload in
      payload.removeValue(forKey: "client_status")
    }
    XCTAssertThrowsError(try attestation(jwt).decodeAsClientAttestationClaims()) { error in
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
    XCTAssertThrowsError(try attestation(jwt).decodeAsClientAttestationClaims()) { error in
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
    XCTAssertThrowsError(try attestation(jwt).decodeAsClientAttestationClaims()) { error in
      guard case ClientAttestationError.invalidStatusListReference = error else {
        XCTFail("Expected invalidStatusListReference, got \(error)"); return
      }
    }
  }

  func testWIA_blankWalletName_shouldFail() throws {
    let jwt = try makeWIAJWT { payload in
      payload["wallet_name"] = "   "
    }
    XCTAssertThrowsError(try attestation(jwt).decodeAsClientAttestationClaims()) { error in
      guard case ClientAttestationError.blankClaim(let name) = error, name == "wallet_name" else {
        XCTFail("Expected blankClaim(wallet_name), got \(error)"); return
      }
    }
  }

  func testWIA_missingIssuer_shouldFail() throws {
    let jwt = try makeWIAJWT { payload in
      payload.removeValue(forKey: "iss")
    }
    XCTAssertThrowsError(try attestation(jwt).decodeAsClientAttestationClaims()) { error in
      guard case ClientAttestationError.missingIssuerClaim = error else {
        XCTFail("Expected missingIssuerClaim, got \(error)"); return
      }
    }
  }

  func testWIA_missingSubject_shouldFail() throws {
    let jwt = try makeWIAJWT { payload in
      payload.removeValue(forKey: "sub")
    }
    XCTAssertThrowsError(try attestation(jwt).decodeAsClientAttestationClaims()) { error in
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
    XCTAssertThrowsError(try attestation(jwt).decodeAsClientAttestationClaims()) { error in
      guard case ClientAttestationError.invalidStatusListReference = error else {
        XCTFail("Expected invalidStatusListReference, got \(error)"); return
      }
    }
  }

  // MARK: - AS algorithm cross-check (ensureSupportedByAuthorizationServer)

  private func makeAttestedClient(
    attestationAlg: JWSAlgorithm.AlgorithmType = .ES256,
    popAlg: SignatureAlgorithm = .ES256
  ) throws -> Client {
    let privateKey = try KeyController.generateECDHPrivateKey()
    let jwk = try ECPublicKey(publicKey: try KeyController.generateECDHPublicKey(from: privateKey))
    return try .attested(
      id: "test-client",
      alg: .init(attestationAlg),
      jwk: jwk,
      popJwtSpec: .init(signingAlgorithm: popAlg, duration: 300, typ: "oauth-client-attestation-pop+jwt"),
      clientAttestationProvider: { _ in
        fatalError("provider must not be invoked from ensureSupportedByAuthorizationServer")
      }
    )
  }

  private func makeAuthorizationServerMetadata(
    tokenEndpointAuthMethods: [String]? = ["attest_jwt_client_auth"],
    attestationAlgs: [String]? = ["ES256"],
    popAlgs: [String]? = ["ES256"]
  ) -> IdentityAndAccessManagementMetadata {
    .oauth(AuthorizationServerMetadata(
      tokenEndpointAuthMethodsSupported: tokenEndpointAuthMethods,
      clientAttestationSigningAlgValuesSupported: attestationAlgs,
      clientAttestationPopSigningAlgValuesSupported: popAlgs
    ))
  }

  func testEnsureSupportedByAS_acceptsMatchingAlgorithms() throws {
    let client = try makeAttestedClient(attestationAlg: .ES256, popAlg: .ES256)
    let metadata = makeAuthorizationServerMetadata(
      attestationAlgs: ["ES256", "ES384"],
      popAlgs: ["ES256"]
    )
    XCTAssertNoThrow(try client.ensureSupportedByAuthorizationServer(metadata))
  }

  func testEnsureSupportedByAS_rejectsUnsupportedAttestationAlg() throws {
    let client = try makeAttestedClient(attestationAlg: .ES512, popAlg: .ES256)
    let metadata = makeAuthorizationServerMetadata(
      attestationAlgs: ["ES256"],
      popAlgs: ["ES256"]
    )
    XCTAssertThrowsError(try client.ensureSupportedByAuthorizationServer(metadata)) { error in
      guard case ValidationError.error(let reason) = error else {
        XCTFail("Expected ValidationError.error, got \(error)"); return
      }
      XCTAssertTrue(reason.contains("ES512"))
      XCTAssertTrue(reason.contains("Client Attestation JWS Algorithm"))
    }
  }

  func testEnsureSupportedByAS_rejectsUnsupportedPopAlg() throws {
    let client = try makeAttestedClient(attestationAlg: .ES256, popAlg: .ES384)
    let metadata = makeAuthorizationServerMetadata(
      attestationAlgs: ["ES256"],
      popAlgs: ["ES256"]
    )
    XCTAssertThrowsError(try client.ensureSupportedByAuthorizationServer(metadata)) { error in
      guard case ValidationError.error(let reason) = error else {
        XCTFail("Expected ValidationError.error, got \(error)"); return
      }
      XCTAssertTrue(reason.contains("ES384"))
      XCTAssertTrue(reason.contains("POP JWS Algorithm"))
    }
  }

  func testEnsureSupportedByAS_rejectsWhenAttestationAlgsMissing() throws {
    let client = try makeAttestedClient()
    let metadata = makeAuthorizationServerMetadata(
      attestationAlgs: nil,
      popAlgs: ["ES256"]
    )
    XCTAssertThrowsError(try client.ensureSupportedByAuthorizationServer(metadata)) { error in
      guard case ValidationError.error(let reason) = error else {
        XCTFail("Expected ValidationError.error, got \(error)"); return
      }
      XCTAssertTrue(reason.contains("Client Attestation JWS Algorithm"))
    }
  }

  func testEnsureSupportedByAS_rejectsWhenPopAlgsMissing() throws {
    let client = try makeAttestedClient()
    let metadata = makeAuthorizationServerMetadata(
      attestationAlgs: ["ES256"],
      popAlgs: nil
    )
    XCTAssertThrowsError(try client.ensureSupportedByAuthorizationServer(metadata)) { error in
      guard case ValidationError.error(let reason) = error else {
        XCTFail("Expected ValidationError.error, got \(error)"); return
      }
      XCTAssertTrue(reason.contains("POP JWS Algorithm"))
    }
  }

  func testEnsureSupportedByAS_rejectsWhenAuthMethodMissing() throws {
    let client = try makeAttestedClient()
    let metadata = makeAuthorizationServerMetadata(
      tokenEndpointAuthMethods: ["client_secret_basic"]
    )
    XCTAssertThrowsError(try client.ensureSupportedByAuthorizationServer(metadata)) { error in
      guard case ValidationError.error(let reason) = error else {
        XCTFail("Expected ValidationError.error, got \(error)"); return
      }
      XCTAssertTrue(reason.contains("attest_jwt_client_auth"))
    }
  }

  func testEnsureSupportedByAS_publicClientIsUnchecked() throws {
    let client = Client(public: "public-client")
    let metadata = makeAuthorizationServerMetadata(
      tokenEndpointAuthMethods: [],
      attestationAlgs: nil,
      popAlgs: nil
    )
    XCTAssertNoThrow(try client.ensureSupportedByAuthorizationServer(metadata))
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
