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
@testable import OpenID4VCI

let CREDENTIAL_ISSUER_PUBLIC_URL = "https://dev.issuer-backend.eudiw.dev"
let MDL_config_id = "org.iso.18013.5.1.mDL"
let PID_MsoMdoc_config_id = "eu.europa.ec.eudi.pid_mso_mdoc"
let PID_SdJwtVC_config_id = "eu.europa.ec.eudi.pid_vc_sd_jwt"

//let CREDENTIAL_ISSUER_PUBLIC_URL = "https://dev.issuer.eudiw.dev"
//let PID_SdJwtVC_config_id = "eu.europa.ec.eudi.mdl_jwt_vc_json"
//let PID_MsoMdoc_config_id = "eu.europa.ec.eudi.pid_mdoc"
//let MDL_config_id = "eu.europa.ec.eudi.mdl_mdoc"

//let CredentialIssuer_URL = "https://preprod.issuer.eudiw.dev/oidc"
//let PID_SdJwtVC_SCOPE = "eu.europa.ec.eudi.pid_jwt_vc_json"
//let PID_MsoMdoc_SCOPE = "eu.europa.ec.eudi.pid_mdoc"
//let PID_mDL_SCOPE = "eu.europa.ec.eudi.mdl_mdoc"

let CREDENTIAL_OFFER_QR_CODE_URL = """
eudi-openid4ci://credentialsOffer?credential_offer=%7B%22credential_issuer%22:%22https://dev.issuer-backend.eudiw.dev%22,%22credential_configuration_ids%22:[%22eu.europa.ec.eudi.pid_mso_mdoc%22,%22eu.europa.ec.eudi.pid_vc_sd_jwt%22,%22org.iso.18013.5.1.mDL%22],%22grants%22:%7B%22authorization_code%22:%7B%22authorization_server%22:%22https://dev.auth.eudiw.dev/realms/pid-issuer-realm%22%7D%7D%7D
"""

let All_Supported_CredentialOffer = """
    {
      "credential_issuer": "\(CREDENTIAL_ISSUER_PUBLIC_URL)",
      "credential_configuration_ids": [ "\(MDL_config_id)", "\(PID_SdJwtVC_config_id)", "\(PID_MsoMdoc_config_id)" ],
      "grants": {
        "authorization_code": {}
      }
    }
"""

let SdJwtVC_CredentialOffer = """
    {
      "credential_issuer": "\(CREDENTIAL_ISSUER_PUBLIC_URL)",
      "credential_configuration_ids": [ "\(PID_SdJwtVC_config_id)" ],
      "grants": {
        "authorization_code": {}
      }
    }
"""

let MsoMdoc_CredentialOffer = """
    {
      "credential_issuer": "\(CREDENTIAL_ISSUER_PUBLIC_URL)",
      "grants": {
        "authorization_code": {}
      },
      "credential_configuration_ids": [ "\(PID_MsoMdoc_config_id)" ]
    }
"""

let MDL_CredentialOffer = """
    {
      "credential_issuer": "\(CREDENTIAL_ISSUER_PUBLIC_URL)",
      "grants": {
        "authorization_code": {}
      },
      "credential_configuration_ids": [ "\(MDL_config_id)" ]
    }
"""

let config: OpenId4VCIConfig = .init(
  clientId: "wallet-dev",
  authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!, 
  authorizeIssuanceConfig: .favorScopes
)

public struct ActingUser {
  public let username: String
  public let password: String
  
  public init(username: String, password: String) {
    self.username = username
    self.password = password
  }
}


struct TestsConstants {
  
  static let AUTHORIZATION_SERVER_PUBLIC_URL = "https://as.example.com"
  
  static let AUTH_CODE_GRANT_CREDENTIAL_OFFER = """
  {
    "credential_issuer": "\(CREDENTIAL_ISSUER_PUBLIC_URL)",
    "credential_configuration_ids": ["PID_mso_mdoc", "UniversityDegree"],
    "grants": {
      "authorization_code": {
        "issuer_state": "eyJhbGciOiJSU0EtFYUaBy"
      }
    }
  }
  """
  
  static let CREDENTIAL_OFFER_NO_GRANTS = """
  {
    "credential_issuer": "\(CREDENTIAL_ISSUER_PUBLIC_URL)",
    "credential_configuration_ids": ["PID_mso_mdoc", "UniversityDegree"]
  }
  """
  
  static let PRE_AUTH_CODE_GRANT_CREDENTIAL_OFFER = """
  {
    "credential_issuer": "\(CREDENTIAL_ISSUER_PUBLIC_URL)",
    "credential_configuration_ids": ["PID_mso_mdoc", "UniversityDegree"],
    "grants": {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": "eyJhbGciOiJSU0EtFYUaBy",
        "user_pin_required": true
      }
    }
  }
  """
  
  static let unAuthorizedRequest: UnauthorizedRequest = .par(
    .init(
      credentials: (try? [.init(value: "UniversityDegree_JWT")]) ?? [],
      getAuthorizationCodeURL: (try? .init(urlString: "https://example.com?client_id=wallet-dev&request_uri=https://request_uri.example.com&state=5A201471-D088-4544-B1E9-5476E5935A95"))!,
      pkceVerifier: (try? .init(
        codeVerifier: "GVaOE~J~xQmkE4aCKm4RNYviYW5QaFiFOxVv-8enIDL",
        codeVerifierMethod: "S256"))!,
      state: "5A201471-D088-4544-B1E9-5476E5935A95"
    )
  )
  
  static func createMockCredentialOffer() async -> CredentialOffer? {
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
        path: "credential_offer_with_blank_issuer_state",
        extension: "json"
      )),
      credentialIssuerMetadataResolver: credentialIssuerMetadataResolver,
      authorizationServerMetadataResolver: authorizationServerMetadataResolver
    )
    
    return try? await credentialOfferRequestResolver.resolve(
      source: .fetchByReference(url: .stub())
    ).get()
  }
  
  static func createMockCredentialOfferValidEncryption() async -> CredentialOffer? {
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: Fetcher<CredentialIssuerMetadata>(session: NetworkingMock(
        path: "openid-credential-issuer_no_encryption",
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
    
    return try? await credentialOfferRequestResolver.resolve(
      source: .fetchByReference(url: .stub())
    ).get()
  }
  
  static func createMockPreAuthCredentialOffer() async -> CredentialOffer? {
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
    
    return try? await credentialOfferRequestResolver.resolve(
      source: .fetchByReference(url: .stub())
    ).get()
  }
}
