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

/// RFC 9207 iss-parameter validation on the authorization callback path.
final class AuthorizationCallbackIssTests: XCTestCase {

  private let config: OpenId4VCIConfig = attestationConfig

  private func makeIssuer(from offer: CredentialOffer) throws -> Issuer {
    try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: config,
      parPoster: Poster(session: NetworkingMock(path: "pushed_authorization_request_response", extension: "json")),
      tokenPoster: Poster(session: NetworkingMock(path: "access_token_request_response_no_proof", extension: "json")),
      dpopConstructor: dpopConstructor(algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported)
    )
  }

  private func makeAuthorizationRequested(
    expectedIssuer: URL?,
    issParameterRequired: Bool
  ) throws -> AuthorizationRequested {
    AuthorizationRequested(
      credentials: [try .init(value: "UniversityDegree_JWT")],
      authorizationCodeURL: try .init(
        urlString: "https://example.com?client_id=\(WALLET_DEV_CLIENT_ID)&request_uri=https://request_uri.example.com&state=state-1"
      ),
      pkceVerifier: try .init(
        codeVerifier: "GVaOE~J~xQmkE4aCKm4RNYviYW5QaFiFOxVv-8enIDL",
        codeVerifierMethod: "S256"
      ),
      state: "state-1",
      configurationIds: [try .init(value: "my_credential_configuration_id")],
      expectedIssuer: expectedIssuer,
      issParameterRequired: issParameterRequired
    )
  }
}
