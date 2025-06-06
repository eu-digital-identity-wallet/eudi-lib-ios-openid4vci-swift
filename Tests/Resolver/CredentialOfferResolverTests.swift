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
      source: .fetchByReference(url: .stub()),
      policy: .ignoreSigned
    )
    
    // Then
    switch result {
    case .success(let result):
      XCTAssert(result.credentialIssuerIdentifier.url.absoluteString == "https://credential-issuer.example.com")
      XCTAssert(result.credentialIssuerMetadata.deferredCredentialEndpoint?.url.absoluteString == "https://credential-issuer.example.com/credentials/deferred")

      let grants = result.grants!
      switch grants {
      case .preAuthorizedCode(let code):
        XCTAssert(code.preAuthorizedCode == "123456")
        XCTAssert(code.txCode?.length == 6)
        
      default:
        XCTFail()
      }
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
      source: .fetchByReference(url: .stub()),
      policy: .ignoreSigned
    )
    
    // Then
    switch result {
    case .success(let result):
      XCTAssert(result.credentialIssuerIdentifier.url.absoluteString == "https://credential-issuer.example.com")
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
      source: .fetchByReference(url: .stub()),
      policy: .ignoreSigned
    )
    
    // Then
    switch result {
    case .success:
      XCTAssert(false)

    case .failure(let error):
      XCTAssert(true, error.localizedDescription)
    }
  }
  
  func testCredentialIssuerParsingWithStandardData() async throws {
    
    // Given
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: Fetcher<CredentialIssuerMetadata>(session: NetworkingMock(
        path: "credential_issuer_metadata",
        extension: "json"
      )
    ))
    
    // When
    let result = try await credentialIssuerMetadataResolver.resolve(
      source: .credentialIssuer(
        try .init("https://credential-issuer.example.com")
      ),
      policy: .ignoreSigned
    )
    
    // Then
    switch result {
    case .success(let result):
      XCTAssert(result.credentialIssuerIdentifier.url.absoluteString == "https://credential-issuer.example.com")
      XCTAssert(result.nonceEndpoint!.url.absoluteString == "https://credential-issuer.example.com/nonce")
      
      let credentialSupported = result.credentialsSupported[try! .init(value: "MobileDrivingLicense_msoMdoc")]!
      
      XCTAssert(result.credentialsSupported.count == 4)
      
      switch credentialSupported {
      case .msoMdoc(let credential):
        let claims = credential.claims
        XCTAssert(claims.count == 4)
        XCTAssert(claims[0].path == ClaimPath.claim("org.iso.18013.5.1").claim("given_name"))
        
      default:
        XCTFail("Expecting mso mdoc")
      }
    case .failure(let error):
      XCTAssert(false, error.localizedDescription)
    }
  }
}
