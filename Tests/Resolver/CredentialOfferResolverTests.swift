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
import JOSESwift

@testable import OpenID4VCI

class CredentialOfferResolverTests: XCTestCase {
  
  func createMetadataFetcher(
    session: Networking = NetworkingMock(
      path: "credential_issuer_metadata",
      extension: "json",
      headers: ["Content-Type": "application/json"]
  )) -> MetadataFetcher {
    MetadataFetcher(
      rawFetcher: RawDataFetcher(
        session: session))
  }
  
  
  func testSignedIssuerMetadataWithInvalidData() async throws {
    let fetcher = MetadataFetcher(
      rawFetcher: RawDataFetcher(
        session: NetworkingMock(
          path: "credential_issuer_metadata_with_signed_invalid",
          extension: "txt",
          headers: ["Content-Type": "application/jwt"]
      )))
  
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: fetcher)
    
    let jwkJSON = """
        {
          "kty": "EC",
          "d": "hmQqQjKufUDXOBaVs-alU0sl1j9_WR1U9ia3J680s2E",
          "crv": "P-256",
          "x": "ilzt0a_ukEX-nl0S05S2RAlbQFL2DSOpTjT3xf52JBY",
          "y": "q-fNv_d0nlZf_S_3S-KmrktIsylB0cybRiL6rZMLZHI"
        }
        """
        
        guard let jsonData = jwkJSON.data(using: .utf8) else {
          XCTAssert(false, "Failed to convert JWK JSON string to Data")
          return
        }
    
    // When
    let result = try await credentialIssuerMetadataResolver.resolve(
      source: .credentialIssuer(CredentialIssuerId("https://credential-issuer.example.com")),
      policy: .requireSigned(issuerTrust: .byPublicKey(jwk: ECPublicKey(data: jsonData))
    ))
    
    switch result {
    case .success(let result):
      XCTAssert(false, "Expected failure but got success: \(result)")
    case .failure(let error):
      if case CredentialIssuerMetadataError.invalidSignedMetadata(let message) = error {
              XCTAssertTrue(message.contains("Invalid 'typ' header"),
                           "Error message should mention invalid 'typ' header")
          } else {
              XCTFail("Expected CredentialIssuerMetadataError.invalidSignedMetadata but got: \(error)")
          }
    }
  }
  
  
  func testSignedIssuerMetadataWithValidData() async throws {
    let fetcher = MetadataFetcher(
      rawFetcher: RawDataFetcher(
        session: NetworkingMock(
          path: "credential_issuer_metadata_with_signed_full",
          extension: "txt",
          headers: ["Content-Type": "application/jwt"]
      )))
  
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: fetcher)
    
    // When
    let result = try await credentialIssuerMetadataResolver.resolve(
      source: 
          .credentialIssuer(
            CredentialIssuerId(
              "https://dev.issuer-backend.eudiw.dev"
            )
          ),
      policy: 
          .requireSigned(
            issuerTrust: .byCertificateChain(
              certificateChainTrust: TestTrust()
            )
          )
    )
    
    switch result {
    case .success(let result):
      print(result)
    case .failure(let error):
      XCTAssert(false, error.localizedDescription)
    }
  }
  
  func testResolutionFailsWhenResponseEncryptionExistsButNoRequestEncryption() async throws {
    
    // Given: Metadata JSON that includes credential_response_encryption but no credential_request_encryption
    let fetcher = MetadataFetcher(
      rawFetcher: RawDataFetcher(
        session: NetworkingMock(
          path: "credential_issuer_metadata_no_request_encryption",
          extension: "json",
          headers: ["Content-Type": "application/json"]
        )))
    
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: fetcher)
    
    // when
    do {
      _ = try await credentialIssuerMetadataResolver.resolve(
        source: .credentialIssuer(CredentialIssuerId(
          "https://credential-issuer.example.com"
        )),
        policy: .ignoreSigned
      )
    } catch let error as CredentialIssuerMetadataError {
      switch error {
      case .credentialRequestEncryptionMustExistIfCredentialResponseEncryptionExists:
        XCTAssertTrue(true)
      default:
        XCTFail("Expected CredentialRequestEncryptionMustExistIfCredentialResponseEncryptionExists but got: \(error)")
      }
    } catch {
      XCTFail("Unexpected error type: \(error)")
    }
  }
    
  func testResolutionSucceedWhenOptionalResponseEncryptionExistsButNoRequestEncryption() async throws {
    
    // Given: Metadata JSON that includes credential_response_encryption but no credential_request_encryption
    let fetcher = MetadataFetcher(
      rawFetcher: RawDataFetcher(
        session: NetworkingMock(
          path: "credential_issuer_metadata_no_request_encryption_optional_response",
          extension: "json",
          headers: ["Content-Type": "application/json"]
        )))
    
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: fetcher)
    
    // When
    let result = try await credentialIssuerMetadataResolver.resolve(
      source:
          .credentialIssuer(
            CredentialIssuerId(
              "https://credential-issuer.example.com"
            )
          ),
      policy: .ignoreSigned
    )
    
    switch result {
    case .success(let result):
      print(result)
    case .failure(let error):
      XCTAssert(false, error.localizedDescription)
    }
  }
  
  func testValidCredentialOfferDataAndOIDVWhenAResolutionIsRequestedSucessWithValidData() async throws {
    
    // Given
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: createMetadataFetcher())
    
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
      fetcher: createMetadataFetcher())
    
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
      fetcher: createMetadataFetcher())
    
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
      fetcher: createMetadataFetcher())
    
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
      
      let credentialSupported = result.credentialsSupported[try .init(value: "MobileDrivingLicense_msoMdoc")]!
      
      XCTAssert(result.credentialsSupported.count == 4)
      
      switch credentialSupported {
      case .msoMdoc(let credential):
        let claims = credential.credentialMetadata?.claims ?? []
        XCTAssert(claims.count == 4)
        XCTAssert(claims[0].path == ClaimPath.claim("org.iso.18013.5.1").claim("given_name"))
        
      default:
        XCTFail("Expecting mso mdoc")
      }
    case .failure(let error):
      XCTAssert(false, error.localizedDescription)
    }
  }
  
  
  func testBuildWellKnownURL_withoutPath() async throws {
      let resolver = CredentialIssuerMetadataResolver()
      let input = URL(string: "https://issuer.example.com")!
      
      let result = try await resolver.buildWellKnownCredentialIssuerURL(from: input)
      
      XCTAssertEqual(
        result.absoluteString,
        "https://issuer.example.com/.well-known/openid-credential-issuer"
      )
    }
    
  func testBuildWellKnownURL_withPath() async throws {
      let resolver = CredentialIssuerMetadataResolver()
      let input = URL(string: "https://issuer.example.com/tenant")!
      
      let result = try await resolver.buildWellKnownCredentialIssuerURL(from: input)
      
      XCTAssertEqual(
        result.absoluteString,
        "https://issuer.example.com/.well-known/openid-credential-issuer/tenant"
      )
    }
    
  func testBuildWellKnownURL_invalidUrl() async {
    let resolver = CredentialIssuerMetadataResolver()
    let input = URL(string: "http://")! // deliberately invalid

    do {
        _ = try await resolver.buildWellKnownCredentialIssuerURL(from: input)
    } catch let error as FetchError {
        switch error {
        case .invalidUrl:
          XCTAssert(true)
        default:
            XCTFail("Unexpected FetchError case: \(error)")
        }
    } catch {
        XCTFail("Unexpected error type: \(error)")
    }
  }

  func testBuildWellKnownURL_withoutTrailingSlash() async throws {
      let resolver = CredentialIssuerMetadataResolver()
      let input = URL(string: "https://issuer.example.com/")!

      let result = try await resolver.buildWellKnownCredentialIssuerURL(from: input)

      XCTAssertEqual(
        result.absoluteString,
        "https://issuer.example.com/.well-known/openid-credential-issuer"
      )
    }

  func testResolvesCredentialOfferWithAuthorizationServerHint() async throws {
    // Given: A credential offer with authorization_server hint that matches metadata
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: createMetadataFetcher()
    )

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
        path: "credential_offer_with_auth_server_hint",
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
    case .success(let credentialOffer):
      XCTAssertEqual(credentialOffer.credentialIssuerIdentifier.url.absoluteString, "https://credential-issuer.example.com")

      // Verify the grants contain the authorization_server
      if case .authorizationCode(let authCode) = credentialOffer.grants {
        XCTAssertEqual(authCode.authorizationServer?.absoluteString, "https://example.com/realms/pid-issuer-realm")
        XCTAssertEqual(authCode.issuerState, "eyJhbGciOiJSU0EtFYUaBy")
      } else {
        XCTFail("Expected authorization_code grant")
      }

    case .failure(let error):
      XCTFail("Expected success but got failure: \(error.localizedDescription)")
    }
  }

  func testFailsWhenAuthorizationServerHintNotInMetadata() async throws {
    // Given: A credential offer with authorization_server hint that does NOT match metadata
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: createMetadataFetcher())

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
        path: "credential_offer_with_invalid_auth_server_hint",
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
      XCTFail("Expected failure when authorization_server hint is not in metadata")

    case .failure(let error):
      // Verify the error message mentions the authorization server not being in the list
      let errorDescription = error.localizedDescription
      XCTAssertTrue(
        errorDescription.contains("not in the list") || errorDescription.contains("authorization server"),
        "Error should mention that authorization server is not in the list: \(errorDescription)"
      )
    }
  }

  func testSelectsSecondAuthServerWhenHintedInMultipleServers() async throws {
    // Given: Metadata with multiple auth servers and offer hints at the second one
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: MetadataFetcher(
        rawFetcher: RawDataFetcher(
          session: NetworkingMock(
            path: "credential_issuer_metadata_multiple_auth_servers",
            extension: "json",
            headers: ["Content-Type": "application/json"]
        ))))

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
        path: "credential_offer_with_second_auth_server_hint",
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
    case .success(let credentialOffer):
      // Verify the grants contain the second authorization_server
      if case .authorizationCode(let authCode) = credentialOffer.grants {
        XCTAssertEqual(authCode.authorizationServer?.absoluteString, "https://auth-server-two.example.com")
      } else {
        XCTFail("Expected authorization_code grant")
      }

    case .failure(let error):
      XCTFail("Expected success but got failure: \(error.localizedDescription)")
    }
  }

  func testResolvesCredentialOfferWithPreAuthorizationServerHint() async throws {
    // Given: A credential offer with authorization_server hint in pre-authorization code flow
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: createMetadataFetcher()
    )

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
        path: "credential_offer_with_pre_auth_server_hint",
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
    case .success(let credentialOffer):
      XCTAssertEqual(credentialOffer.credentialIssuerIdentifier.url.absoluteString, "https://credential-issuer.example.com")

      // Verify the grants contain the authorization_server in pre-auth flow
      if case .preAuthorizedCode(let preAuthCode) = credentialOffer.grants {
        XCTAssertEqual(preAuthCode.authorizationServer?.absoluteString, "https://example.com/realms/pid-issuer-realm")
        XCTAssertEqual(preAuthCode.preAuthorizedCode, "123456")
        XCTAssertEqual(preAuthCode.txCode?.length, 6)
      } else {
        XCTFail("Expected pre-authorized_code grant")
      }

    case .failure(let error):
      XCTFail("Expected success but got failure: \(error.localizedDescription)")
    }
  }

  func testFallsBackToFirstAuthServerWhenNoHintProvided() async throws {
    // Given: A credential offer without authorization_server hint (pre-authorized code flow)
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: MetadataFetcher(
        rawFetcher: RawDataFetcher(
          session: NetworkingMock(
            path: "credential_issuer_metadata_multiple_auth_servers",
            extension: "json",
            headers: ["Content-Type": "application/json"]
        ))))

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

    // When
    let result = await credentialOfferRequestResolver.resolve(
      source: .fetchByReference(url: .stub()),
      policy: .ignoreSigned
    )

    // Then: Should succeed using the first authorization server from metadata
    switch result {
    case .success(let credentialOffer):
      XCTAssertEqual(credentialOffer.credentialIssuerIdentifier.url.absoluteString, "https://credential-issuer.example.com")
      // The first auth server should have been selected
      XCTAssertNotNil(credentialOffer.authorizationServerMetadata)

    case .failure(let error):
      XCTFail("Expected success but got failure: \(error.localizedDescription)")
    }
  }
}
