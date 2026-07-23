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
@preconcurrency import JOSESwift
import SwiftyJSON
@testable import OpenID4VCI

final class IssuanceAuthorizerTests: XCTestCase {

  // MARK: - Missing / multiple / malformed WRPRC

  func testNilIssuerInfoThrowsMissingIssuerInfo() async throws {
    let offer = try makeCredentialOffer(issuerInfo: nil)
    let policy = trustAcceptAllPolicy()
    let authorizer = IssuanceAuthorizer(policy: policy)

    await assertThrows(WRPRCError.missingIssuerInfo) {
      _ = try await authorizer.authorize(credentialOffer: offer)
    }
  }

  func testEmptyIssuerInfoThrowsMissingIssuerInfo() async throws {
    let offer = try makeCredentialOffer(issuerInfo: IssuerInfo(attestations: []))
    let policy = trustAcceptAllPolicy()
    let authorizer = IssuanceAuthorizer(policy: policy)

    await assertThrows(WRPRCError.missingIssuerInfo) {
      _ = try await authorizer.authorize(credentialOffer: offer)
    }
  }

  func testNoWRPRCFormatAttestationsThrowsMissingRequired() async throws {
    let offer = try makeCredentialOffer(issuerInfo: IssuerInfo(attestations: [
      IssuerInfoAttestation(format: "other_format", data: "x")
    ]))
    let authorizer = IssuanceAuthorizer(policy: trustAcceptAllPolicy())

    await assertThrows(WRPRCError.missingRequiredRegistrationCertificate) {
      _ = try await authorizer.authorize(credentialOffer: offer)
    }
  }

  func testMultipleWRPRCAttestationsThrowsMultiple() async throws {
    let offer = try makeCredentialOffer(issuerInfo: IssuerInfo(attestations: [
      IssuerInfoAttestation(format: ETSI119472Part3.REGISTRATION_CERT, data: "one"),
      IssuerInfoAttestation(format: ETSI119472Part3.REGISTRATION_CERT, data: "two")
    ]))
    let authorizer = IssuanceAuthorizer(policy: trustAcceptAllPolicy())

    await assertThrows(WRPRCError.multipleRegistrationCertificates) {
      _ = try await authorizer.authorize(credentialOffer: offer)
    }
  }

  func testMalformedJWTThrowsMalformed() async throws {
    let offer = try makeCredentialOffer(issuerInfo: IssuerInfo(attestations: [
      IssuerInfoAttestation(format: ETSI119472Part3.REGISTRATION_CERT, data: "not.a.jwt")
    ]))
    let authorizer = IssuanceAuthorizer(policy: trustAcceptAllPolicy())

    do {
      _ = try await authorizer.authorize(credentialOffer: offer)
      XCTFail("Expected throw")
    } catch let error as WRPRCError {
      guard case .malformedRegistrationCertificate = error else {
        return XCTFail("Expected .malformedRegistrationCertificate, got \(error)")
      }
    }
  }

  func testWrongTypHeaderThrowsMalformed() async throws {
    let (jwt, _) = try mintTestJWT(typHeader: "some-other-typ")
    let offer = try makeCredentialOffer(issuerInfo: IssuerInfo(attestations: [
      IssuerInfoAttestation(format: ETSI119472Part3.REGISTRATION_CERT, data: jwt)
    ]))
    let authorizer = IssuanceAuthorizer(policy: trustAcceptAllPolicy())

    do {
      _ = try await authorizer.authorize(credentialOffer: offer)
      XCTFail("Expected throw")
    } catch let error as WRPRCError {
      guard case .malformedRegistrationCertificate = error else {
        return XCTFail("Expected .malformedRegistrationCertificate, got \(error)")
      }
    }
  }

  // MARK: - Missing x5c is treated as malformed (WRPRC always requires the WRPAC chain)

  func testMissingX5CThrowsMalformed() async throws {
    let (jwt, _) = try mintTestJWT(
      typHeader: ETSI119475.REG_CERT_HEADER_TYPE,
      payload: ["iat": Date().timeIntervalSince1970]
    )
    let offer = try makeCredentialOffer(issuerInfo: IssuerInfo(attestations: [
      IssuerInfoAttestation(format: ETSI119472Part3.REGISTRATION_CERT, data: jwt)
    ]))
    let authorizer = IssuanceAuthorizer(policy: trustAcceptAllPolicy())

    do {
      _ = try await authorizer.authorize(credentialOffer: offer)
      XCTFail("Expected throw")
    } catch let error as WRPRCError {
      guard case .malformedRegistrationCertificate = error else {
        return XCTFail("Expected .malformedRegistrationCertificate, got \(error)")
      }
    }
  }

  // NOTE: Full happy-path tests (valid signature + policy warnings/errors + time-claim
  // validation) require a real x5c chain — the JWS must carry a base64-DER certificate
  // whose public key matches the signing key. Adding a self-signed cert generation
  // helper is a follow-up; the structural-failure tests above already cover the
  // per-branch authorizer logic up to and including x5c validation.

  // MARK: - Fixture helpers

  private func makeCredentialOffer(issuerInfo: IssuerInfo?) throws -> CredentialOffer {
    let issuerId = try CredentialIssuerId("https://issuer.example.com")
    let configId = try CredentialConfigurationIdentifier(value: "test-cfg")
    let metadata = CredentialIssuerMetadata(
      credentialIssuerIdentifier: issuerId,
      authorizationServers: [URL(string: "https://issuer.example.com")!],
      credentialEndpoint: try CredentialIssuerEndpoint(string: "https://issuer.example.com/credential"),
      deferredCredentialEndpoint: nil,
      nonceEndpoint: nil,
      notificationEndpoint: nil,
      credentialConfigurationsSupported: [:],
      display: nil,
      issuerInfo: issuerInfo
    )
    let asMetadataJSON = """
    {
      "issuer": "https://issuer.example.com",
      "authorization_endpoint": "https://issuer.example.com/authorize",
      "token_endpoint": "https://issuer.example.com/token"
    }
    """
    let asMetadata = try JSONDecoder().decode(
      AuthorizationServerMetadata.self,
      from: Data(asMetadataJSON.utf8)
    )
    return try CredentialOffer(
      credentialIssuerIdentifier: issuerId,
      credentialIssuerMetadata: metadata,
      credentialConfigurationIdentifiers: [configId],
      grants: nil,
      authorizationServerMetadata: .oauth(asMetadata)
    )
  }

  /// Trust that accepts any chain — used to isolate authorizer failure paths from crypto.
  /// The authorizer will still reject before reaching trust when structural checks fail.
  private func trustAcceptAllPolicy() -> RegistrationCertificatePolicy {
    let acceptAll = AcceptAllChainTrust()
    return RegistrationCertificatePolicy(
      issuerTrust: .byCertificateChain(certificateChainTrust: acceptAll),
      authorize: { _, _, _ in .granted(warnings: []) }
    )
  }

  /// Mints a self-signed ES256 JWT with a configurable `typ` and payload.
  /// Returns the compact-serialized JWT and the corresponding public JWK.
  private func mintTestJWT(
    typHeader: String,
    payload: [String: Any] = ["iat": Date().timeIntervalSince1970]
  ) throws -> (jwt: String, publicJWK: JWK) {
    let privateKey = try KeyController.generateECDHPrivateKey()
    let publicSecKey = try KeyController.generateECDHPublicKey(from: privateKey)
    let publicJWK = try ECPublicKey(
      publicKey: publicSecKey,
      additionalParameters: ["alg": "ES256", "use": "sig"]
    )

    let header = try JWSHeader(parameters: [
      "alg": SignatureAlgorithm.ES256.rawValue,
      "typ": typHeader
    ])
    let payloadData = try JSONSerialization.data(withJSONObject: payload, options: [])
    guard let signer = Signer(signatureAlgorithm: .ES256, key: privateKey) else {
      throw XCTError("Unable to build signer")
    }
    let jws = try JWS(header: header, payload: Payload(payloadData), signer: signer)
    return (jws.compactSerializedString, publicJWK)
  }

  private func assertThrows(
    _ expected: WRPRCError,
    _ block: () async throws -> Void
  ) async {
    do {
      try await block()
      XCTFail("Expected \(expected) to be thrown")
    } catch let error as WRPRCError {
      switch (error, expected) {
      case (.missingIssuerInfo, .missingIssuerInfo),
           (.missingRequiredRegistrationCertificate, .missingRequiredRegistrationCertificate),
           (.multipleRegistrationCertificates, .multipleRegistrationCertificates),
           (.registrationCertificateNotTrusted, .registrationCertificateNotTrusted):
        return
      case (.malformedRegistrationCertificate, .malformedRegistrationCertificate),
           (.policyNotMet, .policyNotMet):
        return
      default:
        XCTFail("Expected \(expected), got \(error)")
      }
    } catch {
      XCTFail("Expected WRPRCError, got \(error)")
    }
  }
}

/// Trust stub that accepts any chain. `@unchecked Sendable` — stateless and safe.
private final class AcceptAllChainTrust: CertificateChainTrust, @unchecked Sendable {
  func isValid(chain: [String]) async -> Bool { true }
}

private struct XCTError: Error {
  let message: String
  init(_ message: String) { self.message = message }
}
