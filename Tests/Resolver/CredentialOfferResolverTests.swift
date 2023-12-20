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
  
  func testValidCredentialOfferDataAndOIDVWhenAResolutionIsRequestedSucessWithValidData() async throws {
    
    // Given
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
        path: "test",
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
    
    // When
    let result = await credentialOfferRequestResolver.resolve(
      source: .fetchByReference(url: .stub())
    )
    
    // Then
    switch result {
    case .success(let result):
      XCTAssert(result.credentialIssuerIdentifier.url.absoluteString == "https://credential-issuer.example.com")
      XCTAssert(result.credentialIssuerMetadata.batchCredentialEndpoint?.url.absoluteString == "https://credential-issuer.example.com/credentials/batch")
      XCTAssert(result.credentialIssuerMetadata.deferredCredentialEndpoint?.url.absoluteString == "https://credential-issuer.example.com/credentials/deferred")

    case .failure(let error):
      XCTAssert(false, error.localizedDescription)
    }
  }
  
  func testValidCredentialOfferDataAndOAUTHWhenAResolutionIsRequestedSucessWithValidData() async throws {
    
    // Given
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: Fetcher<CredentialIssuerMetadata>(session: NetworkingMock(
        path: "credential_issuer_metadata",
        extension: "json"
      )
    ))
    
    let authorizationServerMetadataResolver = AuthorizationServerMetadataResolver(
      oidcFetcher: Fetcher<OIDCProviderMetadata>(session: NetworkingMock(
        path: "test",
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
    
    // When
    let result = await credentialOfferRequestResolver.resolve(
      source: .fetchByReference(url: .stub())
    )
    
    // Then
    switch result {
    case .success(let result):
      XCTAssert(result.credentialIssuerIdentifier.url.absoluteString == "https://credential-issuer.example.com")
      XCTAssert(result.credentialIssuerMetadata.batchCredentialEndpoint?.url.absoluteString == "https://credential-issuer.example.com/credentials/batch")
      XCTAssert(result.credentialIssuerMetadata.deferredCredentialEndpoint?.url.absoluteString == "https://credential-issuer.example.com/credentials/deferred")

    case .failure(let error):
      XCTAssert(false, error.localizedDescription)
    }
  }
  
  func testInvalidCredentialOfferDataAndOAUTHWhenAResolutionIsRequestedSucessWithValidData() async throws {
    
    // Given
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: Fetcher<CredentialIssuerMetadata>(session: NetworkingMock(
        path: "credential_issuer_metadata",
        extension: "json"
      )
    ))
    
    let authorizationServerMetadataResolver = AuthorizationServerMetadataResolver(
      oidcFetcher: Fetcher<OIDCProviderMetadata>(session: NetworkingMock(
        path: "test",
        extension: "json"
      )),
      oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: NetworkingMock(
        path: "oauth_authorization_server_metadata",
        extension: "json"
      ))
    )
    
    let credentialOfferRequestResolver = CredentialOfferRequestResolver(
      fetcher: Fetcher<CredentialOfferRequestObject>(session: NetworkingMock(
        path: "invalid_credential_issuer_metadata",
        extension: "json"
      )),
      credentialIssuerMetadataResolver: credentialIssuerMetadataResolver,
      authorizationServerMetadataResolver: authorizationServerMetadataResolver
    )
    
    // When
    let result = await credentialOfferRequestResolver.resolve(
      source: .fetchByReference(url: .stub())
    )
    
    // Then
    switch result {
    case .success:
      XCTAssert(false)

    case .failure(let error):
      XCTAssert(true, error.localizedDescription)
    }
  }
}
