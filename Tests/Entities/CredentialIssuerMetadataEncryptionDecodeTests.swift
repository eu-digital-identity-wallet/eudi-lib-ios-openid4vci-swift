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

/// Locks in the invariant that a present-but-invalid encryption block on the
/// credential-issuer metadata surfaces its decode error to the caller instead
/// of silently downgrading to `.notSupported`.
final class CredentialIssuerMetadataEncryptionDecodeTests: XCTestCase {

  private func decodeMetadata(_ json: String) throws -> CredentialIssuerMetadata {
    try JSONDecoder().decode(
      CredentialIssuerMetadata.self,
      from: Data(json.utf8)
    )
  }

  // A response encryption block that requires encryption but advertises neither algorithms nor
  // methods must fail loudly; previously the nested throw was swallowed by `try?` and turned
  // into `.notSupported`.
  func testResponseEncryptionRequiredWithoutAlgorithmsSurfacesError() {
    let json = """
    {
      "credential_issuer": "https://issuer.example.com",
      "credential_endpoint": "https://issuer.example.com/credentials",
      "credential_response_encryption": {
        "encryption_required": true
      }
    }
    """

    XCTAssertThrowsError(try decodeMetadata(json))
  }

  // Same shape on the request side: `encryption_required: true` with no JWKS and no methods
  // must propagate the decode error rather than silently mark the request path as unsupported.
  func testRequestEncryptionRequiredWithoutJWKSSurfacesError() {
    let json = """
    {
      "credential_issuer": "https://issuer.example.com",
      "credential_endpoint": "https://issuer.example.com/credentials",
      "credential_request_encryption": {
        "encryption_required": true
      }
    }
    """

    XCTAssertThrowsError(try decodeMetadata(json))
  }

  // A JWK whose `kty` is neither RSA nor EC (X25519 / OKP is valid per RFC 8037 but not
  // handled by the current wallet decoder) must not silently empty the JWK list. The decode
  // error should reach the caller instead.
  func testRequestEncryptionWithUnsupportedJWKTypeSurfacesError() {
    let json = """
    {
      "credential_issuer": "https://issuer.example.com",
      "credential_endpoint": "https://issuer.example.com/credentials",
      "credential_request_encryption": {
        "encryption_required": false,
        "jwks": {
          "keys": [
            {
              "kty": "OKP",
              "crv": "X25519",
              "kid": "okp-1",
              "x": "MKrJ8UeKlXpBH7RRxOgnihcpwZfcyaK1Rr5s6yiTG0Q"
            }
          ]
        },
        "enc_values_supported": ["A128GCM"]
      }
    }
    """

    XCTAssertThrowsError(try decodeMetadata(json))
  }

  // A missing encryption block must still default to `.notSupported` (unchanged behavior).
  func testMissingEncryptionBlocksDefaultToNotSupported() throws {
    let json = """
    {
      "credential_issuer": "https://issuer.example.com",
      "credential_endpoint": "https://issuer.example.com/credentials"
    }
    """

    let metadata = try decodeMetadata(json)
    XCTAssertTrue(metadata.credentialResponseEncryption.notSupported)
    XCTAssertTrue(metadata.credentialRequestEncryption?.notSupported ?? false)
  }
}
