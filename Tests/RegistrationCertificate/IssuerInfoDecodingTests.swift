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

final class IssuerInfoDecodingTests: XCTestCase {

  private func decode(_ jsonString: String) throws -> IssuerInfo {
    let data = Data(jsonString.utf8)
    return try JSONDecoder().decode(IssuerInfo.self, from: data)
  }

  // MARK: - Array of attestations (normal case)

  func testDecodesArrayOfAttestations() throws {
    let json = """
    [
      {"format": "registration_cert", "data": "eyJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.sig"},
      {"format": "other_format", "data": "someOtherPayload"}
    ]
    """

    let info = try decode(json)

    XCTAssertEqual(info.attestations.count, 2)
    XCTAssertEqual(info.attestations[0].format, "registration_cert")
    XCTAssertEqual(info.attestations[0].data, "eyJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.sig")
    XCTAssertEqual(info.attestations[1].format, "other_format")
  }

  // MARK: - Single attestation object (tolerant)

  func testDecodesSingleAttestationObject() throws {
    let json = """
    {"format": "registration_cert", "data": "jwt.string.here"}
    """

    let info = try decode(json)

    XCTAssertEqual(info.attestations.count, 1)
    XCTAssertEqual(info.attestations[0].format, "registration_cert")
    XCTAssertEqual(info.attestations[0].data, "jwt.string.here")
  }

  // MARK: - Bare JWT string (tolerant)

  func testDecodesBareJWTStringAsWRPRC() throws {
    let json = """
    "eyJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.sig"
    """

    let info = try decode(json)

    XCTAssertEqual(info.attestations.count, 1)
    XCTAssertEqual(info.attestations[0].format, ETSI119472Part3.REGISTRATION_CERT)
    XCTAssertEqual(info.attestations[0].data, "eyJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.sig")
  }

  func testDecodingEmptyStringFails() {
    let json = "\"\""
    XCTAssertThrowsError(try decode(json))
  }

  // MARK: - Failure modes

  func testDecodingNumberFails() {
    let json = "42"
    XCTAssertThrowsError(try decode(json))
  }

  func testDecodingBoolFails() {
    let json = "true"
    XCTAssertThrowsError(try decode(json))
  }

  func testDecodingNullFails() {
    let json = "null"
    XCTAssertThrowsError(try decode(json))
  }

  // MARK: - Empty array is allowed at decode time

  func testDecodesEmptyArray() throws {
    let json = "[]"
    let info = try decode(json)
    XCTAssertTrue(info.attestations.isEmpty)
  }

  // MARK: - Optional inside enclosing metadata

  func testIssuerInfoIsOptionalInMetadata() throws {
    // Metadata without issuer_info should decode with issuerInfo == nil.
    let json = """
    {
      "credential_issuer": "https://issuer.example.com",
      "authorization_servers": ["https://as.example.com"],
      "credential_endpoint": "https://issuer.example.com/credential"
    }
    """

    let metadata = try JSONDecoder().decode(CredentialIssuerMetadata.self, from: Data(json.utf8))
    XCTAssertNil(metadata.issuerInfo)
  }

  func testIssuerInfoIsPopulatedFromMetadataWhenPresent() throws {
    let json = """
    {
      "credential_issuer": "https://issuer.example.com",
      "authorization_servers": ["https://as.example.com"],
      "credential_endpoint": "https://issuer.example.com/credential",
      "issuer_info": [
        {"format": "registration_cert", "data": "eyJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE2ODMwMDAwMDB9.sig"}
      ]
    }
    """

    let metadata = try JSONDecoder().decode(CredentialIssuerMetadata.self, from: Data(json.utf8))
    XCTAssertNotNil(metadata.issuerInfo)
    XCTAssertEqual(metadata.issuerInfo?.attestations.count, 1)
    XCTAssertEqual(metadata.issuerInfo?.attestations.first?.format, "registration_cert")
  }
}
