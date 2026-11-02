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
@preconcurrency import JOSESwift

@testable import OpenID4VCI

/// OID4VCI §12.2.4: `credential_issuer` must be identical to the identifier the metadata was
/// requested for, using a simple string comparison with no normalization. On a mismatch the
/// response must not be used.
final class CredentialIssuerMetadataResolverIdentifierTests: XCTestCase {

  private let requestedId = "https://issuer.example"
  private let evilId = "https://evil.example"

  // MARK: - JSON responses

  func testJSONResponseWithDifferentCredentialIssuerIsRejected() async throws {
    try await assertMismatch(
      requested: requestedId,
      actual: evilId,
      response: try jsonResponse(credentialIssuer: evilId),
      policy: .ignoreSigned
    )
  }

  func testJSONResponseIsNotNormalizedBeforeComparison() async throws {
    for (requested, actual) in notIdenticalIdentifiers {
      try await assertMismatch(
        requested: requested,
        actual: actual,
        response: try jsonResponse(credentialIssuer: actual),
        policy: .ignoreSigned
      )
    }
  }

  func testJSONResponseWithMatchingCredentialIssuerDecodes() async throws {
    let metadata = try await process(
      try jsonResponse(credentialIssuer: requestedId),
      policy: .ignoreSigned,
      requested: requestedId
    )

    XCTAssertEqual(metadata.credentialIssuerIdentifier.url.absoluteString, requestedId)
  }

  func testJSONResponseWithMatchingPathAndTrailingSlashDecodes() async throws {
    let identifier = "https://issuer.example/tenant/"

    let metadata = try await process(
      try jsonResponse(credentialIssuer: identifier),
      policy: .ignoreSigned,
      requested: identifier
    )

    XCTAssertEqual(metadata.credentialIssuerIdentifier.url.absoluteString, identifier)
  }

  // MARK: - Signed JWT responses

  func testSignedResponseWithMatchingSubButDifferentCredentialIssuerIsRejected() async throws {
    try await assertMismatch(
      requested: requestedId,
      actual: evilId,
      response: try await signedResponse(subject: requestedId, credentialIssuer: evilId),
      policy: signedPolicy
    )
  }

  func testSignedResponseIsNotNormalizedBeforeComparison() async throws {
    for (requested, actual) in notIdenticalIdentifiers {
      try await assertMismatch(
        requested: requested,
        actual: actual,
        response: try await signedResponse(subject: requested, credentialIssuer: actual),
        policy: signedPolicy
      )
    }
  }

  func testSignedResponseWithMatchingCredentialIssuerDecodes() async throws {
    let metadata = try await process(
      try await signedResponse(subject: requestedId, credentialIssuer: requestedId),
      policy: signedPolicy,
      requested: requestedId
    )

    XCTAssertEqual(metadata.credentialIssuerIdentifier.url.absoluteString, requestedId)
  }

  // MARK: - Resolver

  func testResolverFailsOnMismatchAndKeepsNothing() async throws {
    let session = SequencedNetworking(responses: [
      try jsonResponse(credentialIssuer: evilId).data,
      try jsonResponse(credentialIssuer: evilId).data,
      try jsonResponse(credentialIssuer: requestedId).data
    ])
    let resolver = CredentialIssuerMetadataResolver(
      fetcher: MetadataFetcher(rawFetcher: RawDataFetcher(session: session))
    )
    let source: CredentialIssuerSource = .credentialIssuer(try CredentialIssuerId(requestedId))

    for _ in 0..<2 {
      let result = try await resolver.resolve(source: source, policy: .ignoreSigned)
      guard case .failure(.issuerMismatch(let expected, let actual)) = result else {
        XCTFail("Expected issuerMismatch but got \(result)")
        return
      }
      XCTAssertEqual(expected, requestedId)
      XCTAssertEqual(actual, evilId)
    }

    // Each resolve went back to the network, so the rejected response was not kept, and a later
    // good response is what the caller gets.
    let result = try await resolver.resolve(source: source, policy: .ignoreSigned)
    guard case .success(let metadata) = result else {
      XCTFail("Expected success but got \(result)")
      return
    }
    XCTAssertEqual(metadata.credentialIssuerIdentifier.url.absoluteString, requestedId)
    XCTAssertEqual(session.requestCount, 3)
  }
}

private extension CredentialIssuerMetadataResolverIdentifierTests {

  /// Pairs that differ only in ways a normalizing comparison would hide.
  var notIdenticalIdentifiers: [(requested: String, actual: String)] {
    [
      ("https://issuer.example", "https://issuer.example/"),
      ("https://issuer.example/", "https://issuer.example"),
      ("https://issuer.example", "https://ISSUER.example"),
      ("https://issuer.example/tenant", "https://issuer.example/Tenant"),
      ("https://issuer.example/a%20b", "https://issuer.example/a b")
    ]
  }

  var signedPolicy: IssuerMetadataPolicy {
    .requireSigned(issuerTrust: .byCertificateChain(certificateChainTrust: TestTrust()))
  }

  func process(
    _ response: RawFetchResponse,
    policy: IssuerMetadataPolicy,
    requested: String
  ) async throws -> CredentialIssuerMetadata {
    try await MetadataProcessor().processMetadata(
      rawResponse: response,
      policy: policy,
      issuerId: try CredentialIssuerId(requested)
    )
  }

  func assertMismatch(
    requested: String,
    actual: String,
    response: RawFetchResponse,
    policy: IssuerMetadataPolicy,
    file: StaticString = #filePath,
    line: UInt = #line
  ) async {
    do {
      let metadata = try await process(response, policy: policy, requested: requested)
      XCTFail("Expected issuerMismatch for \(actual) but got \(metadata)", file: file, line: line)
    } catch CredentialIssuerMetadataError.issuerMismatch(let expectedValue, let actualValue) {
      XCTAssertEqual(expectedValue, requested, file: file, line: line)
      XCTAssertEqual(actualValue, actual, file: file, line: line)
    } catch {
      XCTFail("Expected issuerMismatch for \(actual) but got \(error)", file: file, line: line)
    }
  }

  /// The metadata fixture with `credential_issuer` replaced.
  func metadataClaims(credentialIssuer: String) throws -> [String: Any] {
    let path = try XCTUnwrap(
      Bundle.module.path(forResource: "credential_issuer_metadata", ofType: "json")
    )
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    var claims = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    claims["credential_issuer"] = credentialIssuer
    return claims
  }

  func jsonResponse(credentialIssuer: String) throws -> RawFetchResponse {
    RawFetchResponse(
      data: try JSONSerialization.data(
        withJSONObject: try metadataClaims(credentialIssuer: credentialIssuer)
      ),
      headers: ["Content-Type": "application/json"]
    )
  }

  /// A metadata JWT per OID4VCI §12.2.3, with its signature valid for the `x5c` leaf, so a
  /// rejection can only come from the claims.
  func signedResponse(subject: String, credentialIssuer: String) async throws -> RawFetchResponse {
    var claims = try metadataClaims(credentialIssuer: credentialIssuer)
    claims[JWTClaimNames.subject] = subject
    claims[JWTClaimNames.issuedAt] = Int(Date().timeIntervalSince1970)

    let header: JWSHeader = try .init(parameters: [
      "alg": "ES256",
      "typ": Constants.SIGNED_METADATA_JWT_TYPE,
      "x5c": [TestsConstants.keyAttestationCertificate]
    ])
    let payload = Payload(try JSONSerialization.data(withJSONObject: claims))
    let jws = try JWS(
      header: header,
      payload: payload,
      signer: await BindingKey.createSigner(
        with: header,
        and: payload,
        for: .secKey(TestsConstants.keyAttestationPrivateKey),
        and: .ES256
      )
    )

    return RawFetchResponse(
      data: Data(jws.compactSerializedString.utf8),
      headers: ["Content-Type": "application/jwt"]
    )
  }
}

/// Returns the given bodies in order and counts the requests it served.
private final class SequencedNetworking: Networking, @unchecked Sendable {

  private let lock = NSLock()
  private var responses: [Data]
  private var served = 0

  init(responses: [Data]) {
    self.responses = responses
  }

  var requestCount: Int {
    lock.withLock { served }
  }

  func data(from url: URL) async throws -> (Data, URLResponse) {
    let body = lock.withLock {
      served += 1
      return responses.removeFirst()
    }
    let response = HTTPURLResponse(
      url: url,
      statusCode: 200,
      httpVersion: nil,
      headerFields: ["Content-Type": "application/json"]
    )
    return (body, response!)
  }

  func data(for request: URLRequest) async throws -> (Data, URLResponse) {
    try await data(from: request.url!)
  }
}
