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
@testable import OpenID4VCI

final class IssuanceAuthorizerTests: XCTestCase {

  // MARK: - Missing / multiple WRPRC

  func testNilIssuerInfoThrowsMissingIssuerInfo() async throws {
    let offer = try makeCredentialOffer(issuerInfo: nil)
    let authorizer = IssuanceAuthorizer(policy: acceptAllPolicy())

    await assertThrows(WRPRCError.missingIssuerInfo) {
      _ = try await authorizer.authorize(credentialOffer: offer)
    }
  }

  func testEmptyIssuerInfoThrowsMissingIssuerInfo() async throws {
    let offer = try makeCredentialOffer(issuerInfo: IssuerInfo(attestations: []))
    let authorizer = IssuanceAuthorizer(policy: acceptAllPolicy())

    await assertThrows(WRPRCError.missingIssuerInfo) {
      _ = try await authorizer.authorize(credentialOffer: offer)
    }
  }

  func testNoWRPRCFormatAttestationsThrowsMissingRequired() async throws {
    let offer = try makeCredentialOffer(issuerInfo: IssuerInfo(attestations: [
      IssuerInfoAttestation(format: "other_format", data: "x")
    ]))
    let authorizer = IssuanceAuthorizer(policy: acceptAllPolicy())

    await assertThrows(WRPRCError.missingRequiredRegistrationCertificate) {
      _ = try await authorizer.authorize(credentialOffer: offer)
    }
  }

  func testMultipleWRPRCAttestationsThrowsMultiple() async throws {
    let offer = try makeCredentialOffer(issuerInfo: IssuerInfo(attestations: [
      IssuerInfoAttestation(format: ETSI119472Part3.REGISTRATION_CERT, data: "one"),
      IssuerInfoAttestation(format: ETSI119472Part3.REGISTRATION_CERT, data: "two")
    ]))
    let authorizer = IssuanceAuthorizer(policy: acceptAllPolicy())

    await assertThrows(WRPRCError.multipleRegistrationCertificates) {
      _ = try await authorizer.authorize(credentialOffer: offer)
    }
  }

  // MARK: - Missing WRPAC

  func testMissingWrpacThrowsMissingWrpac() async throws {
    let offer = try makeCredentialOffer(
      issuerInfo: IssuerInfo(attestations: [
        IssuerInfoAttestation(format: ETSI119472Part3.REGISTRATION_CERT, data: "opaque-wrprc")
      ]),
      wrpac: nil
    )
    let authorizer = IssuanceAuthorizer(policy: acceptAllPolicy())

    await assertThrows(WRPRCError.missingWrpac) {
      _ = try await authorizer.authorize(credentialOffer: offer)
    }
  }

  // MARK: - Policy routing

  func testGrantedReturnsWarningsAsProvided() async throws {
    let offer = try makeCredentialOffer(
      issuerInfo: IssuerInfo(attestations: [
        IssuerInfoAttestation(format: ETSI119472Part3.REGISTRATION_CERT, data: "opaque-wrprc")
      ]),
      wrpac: "opaque-wrpac"
    )
    let expected: [String: [PolicyViolation]] = [
      "test-cfg": [PolicyViolation("w1")],
      "global": [PolicyViolation("w2")]
    ]
    let policy = RegistrationCertificatePolicy { _, _, _ in
      .granted(warnings: expected)
    }
    let authorizer = IssuanceAuthorizer(policy: policy)

    let warnings = try await authorizer.authorize(credentialOffer: offer)
    XCTAssertEqual(warnings, expected)
  }

  func testPolicyReceivesRawWrpacAndWrprc() async throws {
    let offer = try makeCredentialOffer(
      issuerInfo: IssuerInfo(attestations: [
        IssuerInfoAttestation(format: ETSI119472Part3.REGISTRATION_CERT, data: "opaque-wrprc")
      ]),
      wrpac: "opaque-wrpac"
    )
    let received = ReceivedInputs()
    let policy = RegistrationCertificatePolicy { wrpac, wrprc, offered in
      await received.set(wrpac: wrpac, wrprc: wrprc, offered: Array(offered.keys))
      return .granted(warnings: [:])
    }

    _ = try await IssuanceAuthorizer(policy: policy).authorize(credentialOffer: offer)

    let snapshot = await received.snapshot()
    XCTAssertEqual(snapshot.wrpac, "opaque-wrpac")
    XCTAssertEqual(snapshot.wrprc, "opaque-wrprc")
  }

  func testNotGrantedThrowsPolicyNotMet() async throws {
    let offer = try makeCredentialOffer(
      issuerInfo: IssuerInfo(attestations: [
        IssuerInfoAttestation(format: ETSI119472Part3.REGISTRATION_CERT, data: "opaque-wrprc")
      ]),
      wrpac: "opaque-wrpac"
    )
    let policy = RegistrationCertificatePolicy { _, _, _ in
      .notGranted(error: PolicyViolation("boom"))
    }
    let authorizer = IssuanceAuthorizer(policy: policy)

    do {
      _ = try await authorizer.authorize(credentialOffer: offer)
      XCTFail("Expected throw")
    } catch let WRPRCError.policyNotMet(violation) {
      XCTAssertEqual(violation, PolicyViolation("boom"))
    } catch {
      XCTFail("Expected WRPRCError.policyNotMet, got \(error)")
    }
  }

  // MARK: - Fixture helpers

  private func makeCredentialOffer(
    issuerInfo: IssuerInfo?,
    wrpac: String? = "opaque-wrpac"
  ) throws -> CredentialOffer {
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
      issuerInfo: issuerInfo,
      wrpac: wrpac
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

  private func acceptAllPolicy() -> RegistrationCertificatePolicy {
    RegistrationCertificatePolicy(authorize: { _, _, _ in .granted(warnings: [:]) })
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
           (.missingWrpac, .missingWrpac),
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

private actor ReceivedInputs {
  private(set) var wrpac: String = ""
  private(set) var wrprc: String = ""
  private(set) var offered: [CredentialConfigurationIdentifier] = []

  func set(wrpac: String, wrprc: String, offered: [CredentialConfigurationIdentifier]) {
    self.wrpac = wrpac
    self.wrprc = wrprc
    self.offered = offered
  }

  func snapshot() -> (wrpac: String, wrprc: String, offered: [CredentialConfigurationIdentifier]) {
    (wrpac, wrprc, offered)
  }
}
