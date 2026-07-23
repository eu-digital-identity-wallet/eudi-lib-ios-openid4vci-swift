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
@testable import OpenID4VCI

/// Sanity checks for the invariant that couples `registrationCertificatePolicy`
/// to `issuerMetadataPolicy = .requireSigned(.byCertificateChain(...))`.
///
/// Negative cases (`.preferSigned`, `.ignoreSigned`, `.requireSigned(.byPublicKey)`)
/// trip a `preconditionFailure` — that terminates the process and isn't cleanly
/// testable in XCTest without extra harnesses. They're documented in
/// `OpenId4VCIConfig.init` and enforced by the same code path exercised by the
/// positive tests here.
final class OpenId4VCIConfigInvariantTests: XCTestCase {

  private let redirectURI = URL(string: "urn:ietf:wg:oauth:2.0:oob")!

  func testPolicyOmittedIsAlwaysValid() {
    // No WRPRC policy configured — every issuerMetadataPolicy value is fine.
    _ = OpenId4VCIConfig(
      client: attestionClient,
      authFlowRedirectionURI: redirectURI,
      issuerMetadataPolicy: .ignoreSigned,
      registrationCertificatePolicy: nil
    )
    _ = OpenId4VCIConfig(
      client: attestionClient,
      authFlowRedirectionURI: redirectURI,
      issuerMetadataPolicy: .preferSigned(issuerTrust: .byCertificateChain(certificateChainTrust: AcceptAllTrust())),
      registrationCertificatePolicy: nil
    )
  }

  func testPolicyWithRequireSignedAndCertificateChainIsValid() {
    // WRPRC policy configured AND metadata must be signed via cert chain —
    // the only combination that yields a WRPAC.
    _ = OpenId4VCIConfig(
      client: attestionClient,
      authFlowRedirectionURI: redirectURI,
      issuerMetadataPolicy: .requireSigned(issuerTrust: .byCertificateChain(certificateChainTrust: AcceptAllTrust())),
      registrationCertificatePolicy: RegistrationCertificatePolicy(
        issuerTrust: .byCertificateChain(certificateChainTrust: AcceptAllTrust()),
        authorize: { _, _, _ in .granted(warnings: []) }
      )
    )
  }
}

private final class AcceptAllTrust: CertificateChainTrust, @unchecked Sendable {
  func isValid(chain: [String]) async -> Bool { true }
}
