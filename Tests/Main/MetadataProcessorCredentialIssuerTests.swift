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

@testable import OpenID4VCI

/// OpenID4VCI 1.0, Section 12.2.4: `credential_issuer` MUST be identical to the
/// Credential Issuer Identifier used to retrieve the metadata, otherwise the
/// metadata MUST NOT be used.
final class MetadataProcessorCredentialIssuerTests: XCTestCase {
  
  // The fixture advertises "credential_issuer": "https://credential-issuer.example.com"
  private func makeFetcher() -> MetadataFetcher {
    MetadataFetcher(
      rawFetcher: RawDataFetcher(
        session: NetworkingMock(
          path: "credential_issuer_metadata",
          extension: "json",
          headers: ["Content-Type": "application/json"]
        )
      )
    )
  }
  
  private func resolve(issuerId: String) async throws -> Result<CredentialIssuerMetadata, CredentialIssuerMetadataError> {
    let resolver = CredentialIssuerMetadataResolver(fetcher: makeFetcher())
    return try await resolver.resolve(
      source: .credentialIssuer(try CredentialIssuerId(issuerId)),
      policy: .ignoreSigned
    )
  }
  
  private func assertIssuerMismatch(
    _ result: Result<CredentialIssuerMetadata, CredentialIssuerMetadataError>,
    expected: String,
    file: StaticString = #filePath,
    line: UInt = #line
  ) {
    switch result {
    case .success:
      XCTFail("Expected issuerMismatch but resolution succeeded", file: file, line: line)
    case .failure(let error):
      guard case .issuerMismatch(let expectedId, let actualId) = error else {
        XCTFail("Expected issuerMismatch but got: \(error)", file: file, line: line)
        return
      }
      XCTAssertEqual(expectedId, expected, file: file, line: line)
      XCTAssertEqual(actualId, "https://credential-issuer.example.com", file: file, line: line)
    }
  }
  
  func testMetadataIsAcceptedWhenCredentialIssuerMatchesIdentifier() async throws {
    let result = try await resolve(issuerId: "https://credential-issuer.example.com")
    
    switch result {
    case .success(let metadata):
      XCTAssertEqual(
        metadata.credentialIssuerIdentifier.url.absoluteString,
        "https://credential-issuer.example.com"
      )
    case .failure(let error):
      XCTFail("Expected success but got: \(error)")
    }
  }
  
  func testMetadataIsRejectedWhenCredentialIssuerPathDiffers() async throws {
    let issuerId = "https://credential-issuer.example.com/tenant-b"
    let result = try await resolve(issuerId: issuerId)
    assertIssuerMismatch(result, expected: issuerId)
  }
  
  func testMetadataIsRejectedWhenCredentialIssuerPortDiffers() async throws {
    let issuerId = "https://credential-issuer.example.com:8443"
    let result = try await resolve(issuerId: issuerId)
    assertIssuerMismatch(result, expected: issuerId)
  }
  
  func testMetadataIsRejectedWhenCredentialIssuerHostDiffers() async throws {
    let issuerId = "https://other-issuer.example.com"
    let result = try await resolve(issuerId: issuerId)
    assertIssuerMismatch(result, expected: issuerId)
  }
  
  func testComparisonIsExactWithoutNormalization() async throws {
    // Trailing slash differs from the fixture value, so it must be rejected.
    let issuerId = "https://credential-issuer.example.com/"
    let result = try await resolve(issuerId: issuerId)
    assertIssuerMismatch(result, expected: issuerId)
  }
}
