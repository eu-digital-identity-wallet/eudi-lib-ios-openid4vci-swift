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

class CredentialOfferResolverTests: XCTestCase {
  
  override func setUp() async throws {
    try await super.setUp()
  }
  
  override func tearDown() {
    super.tearDown()
  }
  
  func testCredentialOfferResolution() async throws {
    
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: Fetcher<CredentialIssuerMetadata>(session: NetworkingMock(
        path: "credential_issuer_metadata",
        extension: "json"
      )
    ))
    
    let authorizationServerMetadataResolver = AuthorizationServerMetadataResolver(
      oidcFetcher: Fetcher<OIDCProviderMetadata>(session: NetworkingMock(
        path: "oidc_authorization_server_metadata",
        extension: "json"
      )),
      oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: NetworkingMock(
        path: "oauth_authorization_server_metadata",
        extension: "json"
      ))
    )
    
    let credentialOfferRequestResolver = CredentialOfferRequestResolver(
      fetcher: Fetcher<CredentialOfferRequestObject>(session: NetworkingMock(
        path: "credential_offer_with_blank_pre_authorized_code",
        extension: "json"
      )),
      credentialIssuerMetadataResolver: credentialIssuerMetadataResolver,
      authorizationServerMetadataResolver: authorizationServerMetadataResolver
    )
    
    let result = await credentialOfferRequestResolver.resolve(
      source: .fetchByReference(url: .stub())
    )
    
    switch result {
    case .success(let result):
      print(result)
    case .failure(let error):
      XCTAssert(false, error.localizedDescription)
    }
  }
}
