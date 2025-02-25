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
import JOSESwift

@testable import OpenID4VCI

let CREDENTIAL_ISSUER_PUBLIC_URL = "https://issuer-backend.eudiw.dev"
let MDL_config_id = "org.iso.18013.5.1.mDL"
let PID_MsoMdoc_config_id = "eu.europa.ec.eudi.pid_mso_mdoc"
let PID_SdJwtVC_config_id = "eu.europa.ec.eudi.pid_vc_sd_jwt"

//let CREDENTIAL_ISSUER_PUBLIC_URL = "https://dev.issuer.eudiw.dev"
//let PID_SdJwtVC_config_id = "eu.europa.ec.eudi.pid_jwt_vc_json"
//let PID_MsoMdoc_config_id = "eu.europa.ec.eudi.pid_mdoc"
//let MDL_config_id = "eu.europa.ec.eudi.mdl_mdoc"

//let CredentialIssuer_URL = "https://preprod.issuer.eudiw.dev/oidc"
//let PID_SdJwtVC_SCOPE = "eu.europa.ec.eudi.pid_jwt_vc_json"
//let PID_MsoMdoc_SCOPE = "eu.europa.ec.eudi.pid_mdoc"
//let PID_mDL_SCOPE = "eu.europa.ec.eudi.mdl_mdoc"

let CREDENTIAL_OFFER_QR_CODE_URL = """
eudi-openid4ci://credentialsOffer?credential_offer=%7B%22credential_issuer%22:%22https://issuer-backend.eudiw.dev%22,%22credential_configuration_ids%22:[%22eu.europa.ec.eudi.pid_mso_mdoc%22,%22eu.europa.ec.eudi.pid_vc_sd_jwt%22,%22org.iso.18013.5.1.mDL%22],%22grants%22:%7B%22authorization_code%22:%7B%22authorization_server%22:%22https://dev.auth.eudiw.dev/realms/pid-issuer-realm%22%7D%7D%7D
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

let clientConfig: OpenId4VCIConfig = .init(
  client: .public(id: "wallet-dev"),
  authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!,
  authorizeIssuanceConfig: .favorScopes
)

let attestationConfig: OpenId4VCIConfig = .init(
  client: try! selfSignedClient(
    clientId: "wallet-dev",
    privateKey: try KeyController.generateECDHPrivateKey()
  ),
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
      state: "5A201471-D088-4544-B1E9-5476E5935A95",
      configurationIds: [try! .init(value: "my_credential_configuration_id")]
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
  
  static func createMockCredentialOfferValidEncryptionWithBatchLimit() async -> CredentialOffer? {
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: Fetcher<CredentialIssuerMetadata>(session: NetworkingMock(
        path: "openid-credential-issuer_no_encryption_batch",
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
  
  static let CNF_JWT = "eyJ4NWMiOlsiTUlJRExUQ0NBcktnQXdJQkFnSVVMOHM1VHM2MzVrNk9oclJGTWxzU1JBU1lvNll3Q2dZSUtvWkl6ajBFQXdJd1hERWVNQndHQTFVRUF3d1ZVRWxFSUVsemMzVmxjaUJEUVNBdElGVlVJREF4TVMwd0t3WURWUVFLRENSRlZVUkpJRmRoYkd4bGRDQlNaV1psY21WdVkyVWdTVzF3YkdWdFpXNTBZWFJwYjI0eEN6QUpCZ05WQkFZVEFsVlVNQjRYRFRJME1URXlPVEV4TWpnek5Wb1hEVEkyTVRFeU9URXhNamd6TkZvd2FURWRNQnNHQTFVRUF3d1VSVlZFU1NCU1pXMXZkR1VnVm1WeWFXWnBaWEl4RERBS0JnTlZCQVVUQXpBd01URXRNQ3NHQTFVRUNnd2tSVlZFU1NCWFlXeHNaWFFnVW1WbVpYSmxibU5sSUVsdGNHeGxiV1Z1ZEdGMGFXOXVNUXN3Q1FZRFZRUUdFd0pWVkRCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQkFXYTlVYXI3b1AxWmJHRmJzRkE0ZzMxUHpOR1pjd2gydlI3UENrazBZaUFMNGNocnNsZzljajFrQnlueVppN25acllnUE9KN3gwYXRSRmRreGZYanRDamdnRkRNSUlCUHpBTUJnTlZIUk1CQWY4RUFqQUFNQjhHQTFVZEl3UVlNQmFBRkxOc3VKRVhITmVrR21ZeGgwTGhpOEJBekpVYk1DY0dBMVVkRVFRZ01CNkNIR1JsZGk1cGMzTjFaWEl0WW1GamEyVnVaQzVsZFdScGR5NWtaWFl3RWdZRFZSMGxCQXN3Q1FZSEtJR01YUVVCQmpCREJnTlZIUjhFUERBNk1EaWdOcUEwaGpKb2RIUndjem92TDNCeVpYQnliMlF1Y0d0cExtVjFaR2wzTG1SbGRpOWpjbXd2Y0dsa1gwTkJYMVZVWHpBeExtTnliREFkQmdOVkhRNEVGZ1FVOGVIQS9NWHZreUNGNFExaW91WFAwc3BpTVVnd0RnWURWUjBQQVFIL0JBUURBZ2VBTUYwR0ExVWRFZ1JXTUZTR1VtaDBkSEJ6T2k4dloybDBhSFZpTG1OdmJTOWxkUzFrYVdkcGRHRnNMV2xrWlc1MGFYUjVMWGRoYkd4bGRDOWhjbU5vYVhSbFkzUjFjbVV0WVc1a0xYSmxabVZ5Wlc1alpTMW1jbUZ0WlhkdmNtc3dDZ1lJS29aSXpqMEVBd0lEYVFBd1pnSXhBSmpLU0EzQTdrWU9CWXdKQ09PY3JjYVJDRGVWVGZjdllZQ1I4QWp5blVpMjVJL3Rrc0RDRkE1K21hQ0xmbWtVS1FJeEFPVmpHc2dsdVF3VE41MG85N1dtaWxIYmxXNE44K3FBcm1zQkM4alRJdXRuS2ZjNHlaM3U1UTF1WllJbGJ0S1NyZz09Il0sImtpZCI6IjI3Mjg1NDYwOTcyMTEyMDczMjkzODg2ODI5ODc5OTI0NTAzNDE3NDEwMjkzODUzNCIsInR5cCI6InZjK3NkLWp3dCIsImFsZyI6IkVTMjU2In0.eyJwbGFjZV9vZl9iaXJ0aCI6eyJfc2QiOlsiYldoMGNTdjdDbk9TZjlHczg1TDhPYkN0Y0hRUzRHVXEyYTBqSVdOUTl6byIsImtUbXhLMmFFU2YtbFNLOGpabjR3cDRtMUNsb0pVMmwyUm1ZWFlFR2tscm8iXX0sIl9zZCI6WyItSHZVbDhCQ2RxVHJjLTdyOU82dWdSMUdSSlR5cXdEeDVoVWxTX0M5X2pRIiwiMEgwWllkMm8xUzE4LWNyNnEzTFN6c01VNXpnbEt0RWxMWWNpZDRuTTBNRSIsIjF4YnQyal8zRm5XYmppNnNRbE1XaVV5Z1g0NWluZ2YzRmYzQV80NVdTQW8iLCJBaDZWemg5dExERTZKYkg0TENSdnJ4RV9BVFBMbWtRUlpJS0FtTVRSYktFIiwiRVU5REkzdXlLS3YtX3hRV3drUVVRWUdESVlkX2lGaVJMQ1JfY3lQcFhPOCIsIkY1TkEyT0J6SHFrR1c3RkhGYnZ1dUk5SWVfaVVlcFhMNU9OTWp5TkJpWUEiLCJHZmJrZlRvNDRjQy13aXg0UDFZVGdGX3VZUTMtQmduMkFadWJ1eDhvLXFRIiwiSkhINUFSd3RTZE44d3pncDh5M3NRQmg3SFNYQ2RuckZUa0xWbEhVVlV6USIsIkxwMHR2S1JPRGFhaVoyZjBPMy1SLUk5TjAwNnJ5MGozeExqdDN0MnhLX1EiLCJPTm12VVExYW5TNWtsY2M0QnFMU29oMXFYM0hrOUxESlltMFdCd3hVRDk0IiwiVlIzQXhGQjJqSVRMZUNFQmtvN2JyR3VfdkZPOFM1UHU3cnRBY0REbktPcyIsImNaemtWZ3lZMHJuYWp2X2xhSXM2UmZyaVJkUFozN25KWTJsdkdBa2dsQXciLCJsVmk2OGJNWnBVTF9xV0EweUNESGF1ZlA1dWlEUmpsZno2eXRNdUpBQk1BIiwic3JtSE9xWTE4ZFo1RnBNc3hQdUwxcGUwNEI1ZzcwMjRRUXlSQUZ4cjNWZyJdLCJhZGRyZXNzIjp7Il9zZCI6WyI2OWdNSVIxN1lqMk04YXEyTS1pOUdQLVVlVUpCQ2prLTNTQ2tqN19hSU00IiwiSG9rWEhrVWhuQWNLbFhyODJTb2YtZGdzMXVJemRDYVJQM2ltclJ2STZSTSIsIlRTMEZHR2dtZFE4ZGxOYXVFdEpQQ1MxSllCU3NjYjdVVmY4VXEwNlUwRnciLCJZWnBhaTlldGpNcTNMeHZiOHVBOGIyZUs3WnZYSUU3TWY2RTJoLTRKTUtvIiwiakRVYXVPYjh4NFVMV28xYnFjckw4VEN2bDR6YW9jMFJMVF85TnIyeVdIZyIsIm1mdWZpR2dWTmxXTEhSTFlnY0xIV3Z1VlQ3X2hjem1CMWFmemZ2WUlKNUUiXX0sInZjdCI6InVybjpldS5ldXJvcGEuZWMuZXVkaTpwaWQ6MSIsIl9zZF9hbGciOiJzaGEzLTI1NiIsImlzcyI6Imh0dHBzOi8vZGV2Lmlzc3Vlci1iYWNrZW5kLmV1ZGl3LmRldiIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJjcnYiOiJQLTI1NiIsImtpZCI6IjAxMTU5MkZBLUY1MDEtNEM4OS04RTg3LTQ1NjJGMzNCNkZCRSIsIngiOiJ4OC1STzlNRFRZdG10U2RWV3dZcHc1SUZBYUhPaGRqLVhjeFhYV2RmWnhrIiwieSI6InVVSXB2TGJJWmFKQUFEVnp5U2VJQUxwcExLTzBhdDVfVFVLRTZiWGRUa3MiLCJhbGciOiJFUzI1NiJ9fSwiZXhwIjoxNzM3MDMzNzI4LCJqdGkiOiJpZCIsImF1ZCI6ImF1ZCIsImFnZV9lcXVhbF9vcl9vdmVyIjp7Il9zZCI6WyJxOGhfeE9vaUFxaFczOGhHeDV1ZWIxR1B1QnZFaUs0dUJ0ODUyRTREZUtFIl19fQ.pBDorCaD3rtuqYw6JJLCvxtNd1EAmnhLS2tUwBkJJYin5LdYLcDxbX8euAAcfVMUGio0-FOC2JDFlKSwn5ZQ9g"
}

class TestSinger: AsyncSignerProtocol {
  let privateKey: SecKey
  
  init(privateKey: SecKey) {
    self.privateKey = privateKey
  }
  
  func signAsync(_ header: Data, _ payload: Data) async throws -> Data {
    
    guard
      let jwsHeader = JWSHeader(header),
      let algorithm = jwsHeader.algorithm
    else {
      throw NSError(
        domain: "SignerErrorDomain",
        code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Unable to create signer"]
      )
    }
    
    /// Create the signer
    guard let signer = Signer(
      signatureAlgorithm: algorithm,
      key: privateKey
    ) else {
      throw NSError(
        domain: "SignerErrorDomain",
        code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Unable to create signer"]
      )
    }
    
    let jws = try JWS(
      header: jwsHeader,
      payload: .init(
        payload
      ),
      signer: signer
    )
    
    return jws.signature
  }
}
