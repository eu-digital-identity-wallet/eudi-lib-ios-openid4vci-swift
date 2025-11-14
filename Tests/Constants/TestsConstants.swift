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
@preconcurrency import Foundation
@preconcurrency import JOSESwift
import SwiftyJSON

@testable import OpenID4VCI

let CREDENTIAL_ISSUER_PUBLIC_URL = "https://dev.issuer-backend.eudiw.dev"
let MDL_config_id = "org.iso.18013.5.1.mDL"
let PID_MsoMdoc_config_id = "eu.europa.ec.eudi.pid_mso_mdoc"
let PID_SdJwtVC_config_id = "eu.europa.ec.eudi.pid_vc_sd_jwt"
let PID_SdJwtVC_config_id_deferred = "eu.europa.ec.eudi.pid_vc_sd_jwt_deferred"
let EHIC_SdJwtVC_config_id_deferred = "urn:eudi:ehic:1:dc+sd-jwt-compact"
let EHIC_JwsJson_config_id = "urn:eudi:ehic:1:dc+sd-jwt-jws-json"
let EHIC_JwsCompact_config_id = "urn:eudi:ehic:1:dc+sd-jwt-compact"

// let CREDENTIAL_ISSUER_PUBLIC_URL = "https://dev.issuer.eudiw.dev"
// let PID_SdJwtVC_config_id = "eu.europa.ec.eudi.pid_vc_sd_jwt"
// let PID_MsoMdoc_config_id = "eu.europa.ec.eudi.pid_mdoc"
// let MDL_config_id = "eu.europa.ec.eudi.mdl_mdoc"

// let CredentialIssuer_URL = "https://preprod.issuer.eudiw.dev/oidc"
// let PID_SdJwtVC_SCOPE = "eu.europa.ec.eudi.pid_jwt_vc_json"
// let PID_MsoMdoc_SCOPE = "eu.europa.ec.eudi.pid_mdoc"
// let PID_mDL_SCOPE = "eu.europa.ec.eudi.mdl_mdoc"

let CREDENTIAL_OFFER_QR_CODE_URL = """
eudi-openid4ci://credentialsOffer?credential_offer=%7B%22credential_issuer%22:%22https://dev.issuer-backend.eudiw.dev%22,%22credential_configuration_ids%22:[%22eu.europa.ec.eudi.pid_mso_mdoc%22,%22eu.europa.ec.eudi.pid_vc_sd_jwt%22,%22org.iso.18013.5.1.mDL%22],%22grants%22:%7B%22authorization_code%22:%7B%22authorization_server%22:%22https://dev.auth.eudiw.dev/realms/pid-issuer-realm%22%7D%7D%7D
"""

let SECONDARY_CREDENTIAL_OFFER_QR_CODE_URL = """
eudi-openid4ci://credentialsOffer?credential_offer=%7B%22credential_issuer%22:%22https://dev.issuer.eudiw.dev%22,%22credential_configuration_ids%22:[%22eu.europa.ec.eudi.pid_mdoc%22,%22eu.europa.ec.eudi.pid_jwt_vc_json%22,%22eu.europa.ec.eudi.mdl_mdoc%22],%22grants%22:%7B%22authorization_code%22:%7B%22authorization_server%22:%22https://dev.auth.eudiw.dev/realms/pid-issuer-realm%22%7D%7D%7D
"""

let TERTIARY_CREDENTIAL_OFFER_QR_CODE_URL = """
urn:ietf:wg:oauth:2.0:oob?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fdemo-issuer.wwwallet.org%22%2C%22credential_configuration_ids%22%3A%5B%22urn%3Aeudi%3Aehic%3A1%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%7D%7D%7D
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

let WALLET_DEV_CLIENT_ID = "wallet-dev"

let clientConfig: OpenId4VCIConfig = .init(
  client: .public(id: WALLET_DEV_CLIENT_ID),
  authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!,
  authorizeIssuanceConfig: .favorScopes
)

struct TestTrust: CertificateChainTrust {
  func isValid(chain: [String]) -> Bool {
    true
  }
}

let preferSignedClientConfig: OpenId4VCIConfig = .init(
  client: .public(id: WALLET_DEV_CLIENT_ID),
  authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!,
  authorizeIssuanceConfig: .favorScopes,
  issuerMetadataPolicy: .preferSigned(issuerTrust: .byCertificateChain(certificateChainTrust: TestTrust()))
)

let requireSignedClientConfig: OpenId4VCIConfig = .init(
  client: .public(id: WALLET_DEV_CLIENT_ID),
  authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!,
  authorizeIssuanceConfig: .favorScopes,
  issuerMetadataPolicy: .requireSigned(issuerTrust: .byCertificateChain(certificateChainTrust: TestTrust()))
)

let attestationConfig: OpenId4VCIConfig = .init(
  client: try! selfSignedClient(
    clientId: WALLET_DEV_CLIENT_ID,
    privateKey: try KeyController.generateECDHPrivateKey()
  ),
  authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!,
  authorizeIssuanceConfig: .favorScopes
)

func dpopConstructor(algorithms: [JWSAlgorithm]?) throws -> DPoPConstructorType? {
  
  guard let algorithms = algorithms else {
    return nil
  }
  
  if algorithms.isEmpty {
    return nil
  }
  
  guard algorithms.filter({ $0 == JWSAlgorithm(.ES256)}).first != nil else {
    throw ValidationError.error(
      reason: "Unsupported dpop signing algorithm"
    )
  }
  
  let privateKey = try! KeyController.generateECDHPrivateKey()
  let publicKey = try! KeyController.generateECDHPublicKey(from: privateKey)
  
  let alg = JWSAlgorithm(.ES256)
  let publicKeyJWK = try! ECPublicKey(
    publicKey: publicKey,
    additionalParameters: [
      "alg": alg.name,
      "use": "sig",
      "kid": UUID().uuidString
    ])
  
  let privateKeyProxy: SigningKeyProxy = .secKey(privateKey)
  
  return DPoPConstructor(
    algorithm: alg,
    jwk: publicKeyJWK,
    privateKey: privateKeyProxy
  )
}

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
  
  static let unAuthorizedRequest: AuthorizationRequestPrepared = .prepared(
    .init(
      credentials: (try? [.init(value: "UniversityDegree_JWT")]) ?? [],
      authorizationCodeURL: (try? .init(urlString: "https://example.com?client_id=\(WALLET_DEV_CLIENT_ID)&request_uri=https://request_uri.example.com&state=5A201471-D088-4544-B1E9-5476E5935A95"))!,
      pkceVerifier: (try? .init(
        codeVerifier: "GVaOE~J~xQmkE4aCKm4RNYviYW5QaFiFOxVv-8enIDL",
        codeVerifierMethod: "S256"))!,
      state: "5A201471-D088-4544-B1E9-5476E5935A95",
      configurationIds: [try! .init(value: "my_credential_configuration_id")]
    )
  )
  
  static func createMockCredentialOffer() async -> CredentialOffer? {
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: MetadataFetcher(rawFetcher: RawDataFetcher(session: NetworkingMock(
        path: "credential_issuer_metadata",
        extension: "json",
        headers: ["Content-type": "application/json"]
      ))))
    
    let authorizationServerMetadataResolver = AuthorizationServerMetadataResolver(
      oidcFetcher: Fetcher<OIDCProviderMetadata>(session: NetworkingMock(
        path: "oidc_authorization_server_metadata",
        extension: "json"
      )),
      oauthFetcher: Fetcher<AuthorizationServerMetadata>()
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
      source: .fetchByReference(url: .stub()),
      policy: .ignoreSigned
    ).get()
  }
  
  static func createMockCredentialOfferValidEncryption() async -> CredentialOffer? {
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: MetadataFetcher(rawFetcher: RawDataFetcher(session: NetworkingMock(
        path: "openid-credential-issuer_no_encryption",
        extension: "json",
        headers: ["Content-type": "application/json"]
      ))))
    
    let authorizationServerMetadataResolver = AuthorizationServerMetadataResolver(
      oidcFetcher: Fetcher<OIDCProviderMetadata>(session: NetworkingMock(
        path: "oidc_authorization_server_metadata",
        extension: "json"
      )),
      oauthFetcher: Fetcher<AuthorizationServerMetadata>()
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
      source: .fetchByReference(url: .stub()),
      policy: .ignoreSigned
    ).get()
  }
  
  static func createMockCredentialOfferopenidKeyAttestationRequired() async -> CredentialOffer? {
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: MetadataFetcher(rawFetcher: RawDataFetcher(session: NetworkingMock(
        path: "openid-credential-issuer_key_attestation_required",
        extension: "json",
        headers: ["Content-type": "application/json"]
      ))))
    
    let authorizationServerMetadataResolver = AuthorizationServerMetadataResolver(
      oidcFetcher: Fetcher<OIDCProviderMetadata>(session: NetworkingMock(
        path: "oidc_authorization_server_metadata",
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
      source: .fetchByReference(url: .stub()),
      policy: .ignoreSigned
    ).get()
  }
  
  static func createMockCredentialOfferValidEncryptionWithBatchLimit() async -> CredentialOffer? {
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: MetadataFetcher(rawFetcher: RawDataFetcher(session: NetworkingMock(
        path: "openid-credential-issuer_no_encryption_batch",
        extension: "json",
        headers: ["Content-type": "application/json"]
      ))))
    
    let authorizationServerMetadataResolver = AuthorizationServerMetadataResolver(
      oidcFetcher: Fetcher<OIDCProviderMetadata>(session: NetworkingMock(
        path: "oidc_authorization_server_metadata",
        extension: "json"
      )),
      oauthFetcher: Fetcher<AuthorizationServerMetadata>()
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
      source: .fetchByReference(url: .stub()),
      policy: .ignoreSigned
    ).get()
  }
  
  static func createMockPreAuthCredentialOffer() async -> CredentialOffer? {
    let credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(
      fetcher: MetadataFetcher(rawFetcher: RawDataFetcher(session: NetworkingMock(
        path: "credential_issuer_metadata",
        extension: "json",
        headers: ["Content-type": "application/json"]
      ))))
    
    let authorizationServerMetadataResolver = AuthorizationServerMetadataResolver(
      oidcFetcher: Fetcher<OIDCProviderMetadata>(session: NetworkingMock(
        path: "oidc_authorization_server_metadata",
        extension: "json"
      )),
      oauthFetcher: Fetcher<AuthorizationServerMetadata>()
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
      source: .fetchByReference(url: .stub()),
      policy: .ignoreSigned
    ).get()
  }
  
  static let CNF_JWT = "eyJ4NWMiOlsiTUlJRExUQ0NBcktnQXdJQkFnSVVMOHM1VHM2MzVrNk9oclJGTWxzU1JBU1lvNll3Q2dZSUtvWkl6ajBFQXdJd1hERWVNQndHQTFVRUF3d1ZVRWxFSUVsemMzVmxjaUJEUVNBdElGVlVJREF4TVMwd0t3WURWUVFLRENSRlZVUkpJRmRoYkd4bGRDQlNaV1psY21WdVkyVWdTVzF3YkdWdFpXNTBZWFJwYjI0eEN6QUpCZ05WQkFZVEFsVlVNQjRYRFRJME1URXlPVEV4TWpnek5Wb1hEVEkyTVRFeU9URXhNamd6TkZvd2FURWRNQnNHQTFVRUF3d1VSVlZFU1NCU1pXMXZkR1VnVm1WeWFXWnBaWEl4RERBS0JnTlZCQVVUQXpBd01URXRNQ3NHQTFVRUNnd2tSVlZFU1NCWFlXeHNaWFFnVW1WbVpYSmxibU5sSUVsdGNHeGxiV1Z1ZEdGMGFXOXVNUXN3Q1FZRFZRUUdFd0pWVkRCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQkFXYTlVYXI3b1AxWmJHRmJzRkE0ZzMxUHpOR1pjd2gydlI3UENrazBZaUFMNGNocnNsZzljajFrQnlueVppN25acllnUE9KN3gwYXRSRmRreGZYanRDamdnRkRNSUlCUHpBTUJnTlZIUk1CQWY4RUFqQUFNQjhHQTFVZEl3UVlNQmFBRkxOc3VKRVhITmVrR21ZeGgwTGhpOEJBekpVYk1DY0dBMVVkRVFRZ01CNkNIR1JsZGk1cGMzTjFaWEl0WW1GamEyVnVaQzVsZFdScGR5NWtaWFl3RWdZRFZSMGxCQXN3Q1FZSEtJR01YUVVCQmpCREJnTlZIUjhFUERBNk1EaWdOcUEwaGpKb2RIUndjem92TDNCeVpYQnliMlF1Y0d0cExtVjFaR2wzTG1SbGRpOWpjbXd2Y0dsa1gwTkJYMVZVWHpBeExtTnliREFkQmdOVkhRNEVGZ1FVOGVIQS9NWHZreUNGNFExaW91WFAwc3BpTVVnd0RnWURWUjBQQVFIL0JBUURBZ2VBTUYwR0ExVWRFZ1JXTUZTR1VtaDBkSEJ6T2k4dloybDBhSFZpTG1OdmJTOWxkUzFrYVdkcGRHRnNMV2xrWlc1MGFYUjVMWGRoYkd4bGRDOWhjbU5vYVhSbFkzUjFjbVV0WVc1a0xYSmxabVZ5Wlc1alpTMW1jbUZ0WlhkdmNtc3dDZ1lJS29aSXpqMEVBd0lEYVFBd1pnSXhBSmpLU0EzQTdrWU9CWXdKQ09PY3JjYVJDRGVWVGZjdllZQ1I4QWp5blVpMjVJL3Rrc0RDRkE1K21hQ0xmbWtVS1FJeEFPVmpHc2dsdVF3VE41MG85N1dtaWxIYmxXNE44K3FBcm1zQkM4alRJdXRuS2ZjNHlaM3U1UTF1WllJbGJ0S1NyZz09Il0sImtpZCI6IjI3Mjg1NDYwOTcyMTEyMDczMjkzODg2ODI5ODc5OTI0NTAzNDE3NDEwMjkzODUzNCIsInR5cCI6InZjK3NkLWp3dCIsImFsZyI6IkVTMjU2In0.eyJwbGFjZV9vZl9iaXJ0aCI6eyJfc2QiOlsiYldoMGNTdjdDbk9TZjlHczg1TDhPYkN0Y0hRUzRHVXEyYTBqSVdOUTl6byIsImtUbXhLMmFFU2YtbFNLOGpabjR3cDRtMUNsb0pVMmwyUm1ZWFlFR2tscm8iXX0sIl9zZCI6WyItSHZVbDhCQ2RxVHJjLTdyOU82dWdSMUdSSlR5cXdEeDVoVWxTX0M5X2pRIiwiMEgwWllkMm8xUzE4LWNyNnEzTFN6c01VNXpnbEt0RWxMWWNpZDRuTTBNRSIsIjF4YnQyal8zRm5XYmppNnNRbE1XaVV5Z1g0NWluZ2YzRmYzQV80NVdTQW8iLCJBaDZWemg5dExERTZKYkg0TENSdnJ4RV9BVFBMbWtRUlpJS0FtTVRSYktFIiwiRVU5REkzdXlLS3YtX3hRV3drUVVRWUdESVlkX2lGaVJMQ1JfY3lQcFhPOCIsIkY1TkEyT0J6SHFrR1c3RkhGYnZ1dUk5SWVfaVVlcFhMNU9OTWp5TkJpWUEiLCJHZmJrZlRvNDRjQy13aXg0UDFZVGdGX3VZUTMtQmduMkFadWJ1eDhvLXFRIiwiSkhINUFSd3RTZE44d3pncDh5M3NRQmg3SFNYQ2RuckZUa0xWbEhVVlV6USIsIkxwMHR2S1JPRGFhaVoyZjBPMy1SLUk5TjAwNnJ5MGozeExqdDN0MnhLX1EiLCJPTm12VVExYW5TNWtsY2M0QnFMU29oMXFYM0hrOUxESlltMFdCd3hVRDk0IiwiVlIzQXhGQjJqSVRMZUNFQmtvN2JyR3VfdkZPOFM1UHU3cnRBY0REbktPcyIsImNaemtWZ3lZMHJuYWp2X2xhSXM2UmZyaVJkUFozN25KWTJsdkdBa2dsQXciLCJsVmk2OGJNWnBVTF9xV0EweUNESGF1ZlA1dWlEUmpsZno2eXRNdUpBQk1BIiwic3JtSE9xWTE4ZFo1RnBNc3hQdUwxcGUwNEI1ZzcwMjRRUXlSQUZ4cjNWZyJdLCJhZGRyZXNzIjp7Il9zZCI6WyI2OWdNSVIxN1lqMk04YXEyTS1pOUdQLVVlVUpCQ2prLTNTQ2tqN19hSU00IiwiSG9rWEhrVWhuQWNLbFhyODJTb2YtZGdzMXVJemRDYVJQM2ltclJ2STZSTSIsIlRTMEZHR2dtZFE4ZGxOYXVFdEpQQ1MxSllCU3NjYjdVVmY4VXEwNlUwRnciLCJZWnBhaTlldGpNcTNMeHZiOHVBOGIyZUs3WnZYSUU3TWY2RTJoLTRKTUtvIiwiakRVYXVPYjh4NFVMV28xYnFjckw4VEN2bDR6YW9jMFJMVF85TnIyeVdIZyIsIm1mdWZpR2dWTmxXTEhSTFlnY0xIV3Z1VlQ3X2hjem1CMWFmemZ2WUlKNUUiXX0sInZjdCI6InVybjpldS5ldXJvcGEuZWMuZXVkaTpwaWQ6MSIsIl9zZF9hbGciOiJzaGEzLTI1NiIsImlzcyI6Imh0dHBzOi8vZGV2Lmlzc3Vlci1iYWNrZW5kLmV1ZGl3LmRldiIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJjcnYiOiJQLTI1NiIsImtpZCI6IjAxMTU5MkZBLUY1MDEtNEM4OS04RTg3LTQ1NjJGMzNCNkZCRSIsIngiOiJ4OC1STzlNRFRZdG10U2RWV3dZcHc1SUZBYUhPaGRqLVhjeFhYV2RmWnhrIiwieSI6InVVSXB2TGJJWmFKQUFEVnp5U2VJQUxwcExLTzBhdDVfVFVLRTZiWGRUa3MiLCJhbGciOiJFUzI1NiJ9fSwiZXhwIjoxNzM3MDMzNzI4LCJqdGkiOiJpZCIsImF1ZCI6ImF1ZCIsImFnZV9lcXVhbF9vcl9vdmVyIjp7Il9zZCI6WyJxOGhfeE9vaUFxaFczOGhHeDV1ZWIxR1B1QnZFaUs0dUJ0ODUyRTREZUtFIl19fQ.pBDorCaD3rtuqYw6JJLCvxtNd1EAmnhLS2tUwBkJJYin5LdYLcDxbX8euAAcfVMUGio0-FOC2JDFlKSwn5ZQ9g"
  
  static let signedMetadata = "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImlsenQwYV91a0VYLW5sMFMwNVMyUkFsYlFGTDJEU09wVGpUM3hmNTJKQlkiLCJ5IjoicS1mTnZfZDBubFpmX1NfM1MtS21ya3RJc3lsQjBjeWJSaUw2clpNTFpISSJ9fQ.eyJzdWIiOiJodHRwczovL2NyZWRlbnRpYWwtaXNzdWVyLmV4YW1wbGUuY29tIiwiZGlzcGxheSI6W3sibmFtZSI6ImNyZWRlbnRpYWwtaXNzdWVyLmV4YW1wbGUuY29tIiwibG9jYWxlIjoiZW4tVVMiLCJsb2dvIjp7InVyaSI6Imh0dHBzOi8vY3JlZGVudGlhbC1pc3N1ZXIuZXhhbXBsZS5jb20vbG9nby5wbmciLCJhbHRfdGV4dCI6IkNyZWRlbnRpYWwgSXNzdWVyIExvZ28ifX1dLCJpc3MiOiJodHRwczovL2NyZWRlbnRpYWwtaXNzdWVyLmV4YW1wbGUuY29tIiwiYmF0Y2hfY3JlZGVudGlhbF9pc3N1YW5jZSI6eyJiYXRjaF9zaXplIjoxNX0sImNyZWRlbnRpYWxfY29uZmlndXJhdGlvbnNfc3VwcG9ydGVkIjp7IlVuaXZlcnNpdHlEZWdyZWVfSldUIjp7ImZvcm1hdCI6Imp3dF92Y19qc29uIiwic2NvcGUiOiJVbml2ZXJzaXR5RGVncmVlX0pXVCIsImNyeXB0b2dyYXBoaWNfYmluZGluZ19tZXRob2RzX3N1cHBvcnRlZCI6WyJkaWQ6ZXhhbXBsZSJdLCJjcmVkZW50aWFsX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTZLIl0sInByb29mX3R5cGVzX3N1cHBvcnRlZCI6eyJqd3QiOnsicHJvb2Zfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJSUzI1NiIsIkVTMjU2Il19fSwiZGlzcGxheSI6W3sibmFtZSI6IlVuaXZlcnNpdHkgQ3JlZGVudGlhbCIsImxvY2FsZSI6ImVuLVVTIiwibG9nbyI6eyJ1cmkiOiJodHRwczovL2V4YW1wbGV1bml2ZXJzaXR5LmNvbS9wdWJsaWMvbG9nby5wbmciLCJhbHRfdGV4dCI6ImEgc3F1YXJlIGxvZ28gb2YgYSB1bml2ZXJzaXR5In0sImJhY2tncm91bmRfY29sb3IiOiIjMTIxMDdjIiwiYmFja2dyb3VuZF9pbWFnZSI6eyJ1cmkiOiJodHRwczovL2V4YW1wbGVzdGF0ZS5jb20vcHVibGljL2JhY2tncm91bmQucG5nIn0sInRleHRfY29sb3IiOiIjRkZGRkZGIn1dLCJjcmVkZW50aWFsX2RlZmluaXRpb24iOnsidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl19LCJjbGFpbXMiOlt7InBhdGgiOlsiZ2l2ZW5fbmFtZSJdLCJkaXNwbGF5IjpbeyJuYW1lIjoiR2l2ZW4gTmFtZSIsImxvY2FsZSI6ImVuLVVTIn1dfSx7InBhdGgiOlsiZmFtaWx5X25hbWUiXSwiZGlzcGxheSI6W3sibmFtZSI6IlN1cm5hbWUiLCJsb2NhbGUiOiJlbi1VUyJ9XX0seyJwYXRoIjpbImRlZ3JlZSJdfSx7InBhdGgiOlsiZ3BhIl0sImRpc3BsYXkiOlt7Im5hbWUiOiJuYW1lIiwibG9jYWxlIjoiR1BBIn1dfV19LCJNb2JpbGVEcml2aW5nTGljZW5zZV9tc29NZG9jIjp7ImZvcm1hdCI6Im1zb19tZG9jIiwic2NvcGUiOiJNb2JpbGVEcml2aW5nTGljZW5zZV9tc29NZG9jIiwiY3J5cHRvZ3JhcGhpY19iaW5kaW5nX21ldGhvZHNfc3VwcG9ydGVkIjpbImNvc2Vfa2V5Il0sImNyZWRlbnRpYWxfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJFUzI1NiIsIkVTMzg0IiwiRVM1MTIiXSwicHJvb2ZfdHlwZXNfc3VwcG9ydGVkIjp7Imp3dCI6eyJwcm9vZl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIlJTMjU2IiwiRVMyNTYiXSwia2V5X2F0dGVzdGF0aW9uc19yZXF1aXJlZCI6e319fSwiZGlzcGxheSI6W3sibmFtZSI6Ik1vYmlsZSBEcml2aW5nIExpY2Vuc2UiLCJsb2NhbGUiOiJlbi1VUyIsImxvZ28iOnsidXJpIjoiaHR0cHM6Ly9leGFtcGxlc3RhdGUuY29tL3B1YmxpYy9tZGwucG5nIiwiYWx0X3RleHQiOiJhIHNxdWFyZSBmaWd1cmUgb2YgYSBtb2JpbGUgZHJpdmluZyBsaWNlbnNlIn0sImJhY2tncm91bmRfY29sb3IiOiIjMTIxMDdjIiwiYmFja2dyb3VuZF9pbWFnZSI6eyJ1cmkiOiJodHRwczovL2V4YW1wbGVzdGF0ZS5jb20vcHVibGljL2JhY2tncm91bmQucG5nIn0sInRleHRfY29sb3IiOiIjRkZGRkZGIn1dLCJkb2N0eXBlIjoib3JnLmlzby4xODAxMy41LjEubURMIiwiY2xhaW1zIjpbeyJwYXRoIjpbIm9yZy5pc28uMTgwMTMuNS4xIiwiZ2l2ZW5fbmFtZSJdLCJkaXNwbGF5IjpbeyJuYW1lIjoiR2l2ZW4gTmFtZSIsImxvY2FsZSI6ImVuLVVTIn1dfSx7InBhdGgiOlsib3JnLmlzby4xODAxMy41LjEiLCJmYW1pbHlfbmFtZSJdLCJkaXNwbGF5IjpbeyJuYW1lIjoiU3VybmFtZSIsImxvY2FsZSI6ImVuLVVTIn1dfSx7InBhdGgiOlsib3JnLmlzby4xODAxMy41LjEiLCJiaXJ0aF9kYXRlIl19LHsicGF0aCI6WyJvcmcuaXNvLjE4MDEzLjUuMS5hYW12YSIsIm9yZ2FuX2Rvbm9yIl19XX0sIlVuaXZlcnNpdHlEZWdyZWVfTERQX1ZDIjp7ImZvcm1hdCI6ImxkcF92YyIsInNjb3BlIjoiVW5pdmVyc2l0eURlZ3JlZV9MRFBfVkMiLCJjcnlwdG9ncmFwaGljX2JpbmRpbmdfbWV0aG9kc19zdXBwb3J0ZWQiOlsiZGlkOmV4YW1wbGUiXSwiY3JlZGVudGlhbF9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVkMjU1MTlTaWduYXR1cmUyMDE4Il0sInByb29mX3R5cGVzX3N1cHBvcnRlZCI6eyJqd3QiOnsicHJvb2Zfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJSUzI1NiIsIkVTMjU2Il0sImtleV9hdHRlc3RhdGlvbnNfcmVxdWlyZWQiOnsia2V5X3N0b3JhZ2UiOlsiaXNvXzE4MDQ1X2hpZ2giLCJpc29fMTgwNDVfZW5oYW5jZWQtYmFzaWMiXX19fSwiZGlzcGxheSI6W3sibmFtZSI6IlVuaXZlcnNpdHkgQ3JlZGVudGlhbCIsImxvY2FsZSI6ImVuLVVTIiwibG9nbyI6eyJ1cmkiOiJodHRwczovL2V4YW1wbGV1bml2ZXJzaXR5LmNvbS9wdWJsaWMvbG9nby5wbmciLCJhbHRfdGV4dCI6ImEgc3F1YXJlIGxvZ28gb2YgYSB1bml2ZXJzaXR5In0sImJhY2tncm91bmRfY29sb3IiOiIjMTIxMDdjIiwidGV4dF9jb2xvciI6IiNGRkZGRkYifV0sImNyZWRlbnRpYWxfZGVmaW5pdGlvbiI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWxfTERQX1ZDIiwiVW5pdmVyc2l0eURlZ3JlZUNyZWRlbnRpYWxfTERQX1ZDIl19LCJjbGFpbXMiOlt7InBhdGgiOlsiZ2l2ZW5fbmFtZSJdLCJkaXNwbGF5IjpbeyJuYW1lIjoiR2l2ZW4gTmFtZSIsImxvY2FsZSI6ImVuLVVTIn1dfSx7InBhdGgiOlsiZmFtaWx5X25hbWUiXSwiZGlzcGxheSI6W3sibmFtZSI6IlN1cm5hbWUiLCJsb2NhbGUiOiJlbi1VUyJ9XX0seyJwYXRoIjpbImRlZ3JlZSJdfSx7InBhdGgiOlsiZ3BhIl0sImRpc3BsYXkiOlt7Im5hbWUiOiJuYW1lIiwibG9jYWxlIjoiR1BBIn1dfV19LCJVbml2ZXJzaXR5RGVncmVlX0pXVF9WQ19KU09OLUxEIjp7ImZvcm1hdCI6Imp3dF92Y19qc29uLWxkIiwic2NvcGUiOiJVbml2ZXJzaXR5RGVncmVlX0pXVF9WQ19KU09OLUxEIiwiY3J5cHRvZ3JhcGhpY19iaW5kaW5nX21ldGhvZHNfc3VwcG9ydGVkIjpbImRpZDpleGFtcGxlIl0sImNyZWRlbnRpYWxfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJFZDI1NTE5U2lnbmF0dXJlMjAxOCJdLCJwcm9vZl90eXBlc19zdXBwb3J0ZWQiOnsiand0Ijp7InByb29mX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiUlMyNTYiLCJFUzI1NiJdLCJrZXlfYXR0ZXN0YXRpb25zX3JlcXVpcmVkIjp7ImtleV9zdG9yYWdlIjpbImlzb18xODA0NV9oaWdoIiwiaXNvXzE4MDQ1X2VuaGFuY2VkLWJhc2ljIl0sInVzZXJfYXV0aGVudGljYXRpb24iOlsiaXNvXzE4MDQ1X2hpZ2giLCJpc29fMTgwNDVfZW5oYW5jZWQtYmFzaWMiXX19fSwiZGlzcGxheSI6W3sibmFtZSI6IlVuaXZlcnNpdHkgQ3JlZGVudGlhbCIsImxvY2FsZSI6ImVuLVVTIiwibG9nbyI6eyJ1cmkiOiJodHRwczovL2V4YW1wbGV1bml2ZXJzaXR5LmNvbS9wdWJsaWMvbG9nby5wbmciLCJhbHRfdGV4dCI6ImEgc3F1YXJlIGxvZ28gb2YgYSB1bml2ZXJzaXR5In0sImJhY2tncm91bmRfY29sb3IiOiIjMTIxMDdjIiwidGV4dF9jb2xvciI6IiNGRkZGRkYifV0sImNyZWRlbnRpYWxfZGVmaW5pdGlvbiI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWxfSldUX1ZDX0pTT04tTEQiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbF9KV1RfVkNfSlNPTi1MRCJdfSwiY2xhaW1zIjpbeyJwYXRoIjpbImdpdmVuX25hbWUiXSwiZGlzcGxheSI6W3sibmFtZSI6IkdpdmVuIE5hbWUiLCJsb2NhbGUiOiJlbi1VUyJ9XX0seyJwYXRoIjpbImZhbWlseV9uYW1lIl0sImRpc3BsYXkiOlt7Im5hbWUiOiJTdXJuYW1lIiwibG9jYWxlIjoiZW4tVVMifV19LHsicGF0aCI6WyJkZWdyZWUiXX0seyJwYXRoIjpbImdwYSJdLCJkaXNwbGF5IjpbeyJuYW1lIjoibmFtZSIsImxvY2FsZSI6IkdQQSJ9XX1dfX0sIm5vbmNlX2VuZHBvaW50IjoiaHR0cHM6Ly9jcmVkZW50aWFsLWlzc3Vlci5leGFtcGxlLmNvbS9zaWduZWQvbm9uY2UiLCJjcmVkZW50aWFsX2lzc3VlciI6Imh0dHBzOi8vY3JlZGVudGlhbC1pc3N1ZXIuZXhhbXBsZS5jb20iLCJjcmVkZW50aWFsX3Jlc3BvbnNlX2VuY3J5cHRpb24iOnsiYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiUlNBLU9BRVAtMjU2Il0sImVuY192YWx1ZXNfc3VwcG9ydGVkIjpbIlhDMjBQIl0sImVuY3J5cHRpb25fcmVxdWlyZWQiOnRydWV9LCJub3RpZmljYXRpb25fZW5kcG9pbnQiOiJodHRwczovL2NyZWRlbnRpYWwtaXNzdWVyLmV4YW1wbGUuY29tL3NpZ25lZC9ub3RpZmljYXRpb24iLCJpYXQiOjE3NDEyNjExMDUsImRlZmVycmVkX2NyZWRlbnRpYWxfZW5kcG9pbnQiOiJodHRwczovL2NyZWRlbnRpYWwtaXNzdWVyLmV4YW1wbGUuY29tL3NpZ25lZC9jcmVkZW50aWFscy9kZWZlcnJlZCIsImF1dGhvcml6YXRpb25fc2VydmVycyI6WyJodHRwczovL2tleWNsb2FrLWV1ZGkubmV0Y29tcGFueS1pbnRyYXNvZnQuY29tL3JlYWxtcy9waWQtaXNzdWVyLXJlYWxtIl0sImNyZWRlbnRpYWxfZW5kcG9pbnQiOiJodHRwczovL2NyZWRlbnRpYWwtaXNzdWVyLmV4YW1wbGUuY29tL3NpZ25lZC9jcmVkZW50aWFscyJ9.47xjabW1UsSqCLLlBRfg3D2oDVfz0gswuqzq6u4EoDlVKmLmjJfc-gvcblh2MeTFkob_c2XpIIj-jyEOq4vj7g"
  
  static let ketAttestationJWT = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtleS1hdHRlc3RhdGlvbitqd3QiLCJ4NWMiOlsiTUlJQlhEQ0NBUUtnQXdJQkFnSVVXZWhpUDJucVY5UWNmRlNFVytNQm1GVlBTcWd3Q2dZSUtvWkl6ajBFQXdJd0xqRUxNQWtHQTFVRUJoTUNWVlF4SHpBZEJnTlZCQU1NRm10bGVTMWhkSFJsYzNSaGRHbHZiaTFwYzNOMVpYSXdIaGNOTWpVd056STVNRGd6TVRVMldoY05Nall3TnpJNU1EZ3pNVFUyV2pBdU1Rc3dDUVlEVlFRR0V3SlZWREVmTUIwR0ExVUVBd3dXYTJWNUxXRjBkR1Z6ZEdGMGFXOXVMV2x6YzNWbGNqQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJCRFwvT1UyNmJxSldzUVB1U1NcL3ljdWEwWmEwcnJqbkZuRlcxTUFoWmpnOW81N2kyWXdQSjZWSFRScU40QlVvcVl4VXFHbmQ2Zk1iZEhGR3hHRk5KZFlZd0NnWUlLb1pJemowRUF3SURTQUF3UlFJaEFMcWgzblJCR2ViNFlQME1nbndpREsxNVJkR3g4cWdLMTQzRkFJUFR5Z3BJQWlBUlF0UkhiRkk0TUZ3YWp6VVlMclpyTVVaVVVSYitsRHZMbjRyb2pDVU41dz09Il19.eyJpYXQiOjE3NTkzMTc5OTksIm5vbmNlIjoiZXlKbGNHc2lPbnNpYTNSNUlqb2lSVU1pTENKamNuWWlPaUpRTFRJMU5pSXNJbmdpT2lKS2NsSmZYMjVLWTJ4MGNITTFNVXBWVGxKNWVrOXVUbWRqTTAxV2RVSlRlVE41UzNSSFZXcEhXazR3SWl3aWVTSTZJbVIzYkhOeE5FVkhWbXBsYW5jMGJUWk5kMU5wVEcxV2NEQm5ObGt0VDAxMFgxTmpSRTh4U1daT05qQWlmU3dpZEhsd0lqb2libTl1WTJVcmFuZDBJaXdpWlc1aklqb2lXRU15TUZBaUxDSmhiR2NpT2lKRlEwUklMVVZUSW4wLi5mb0dQZGtkeDhidDBfMnk5OHdGcjRGakRUbVZMMnRGMy5yODNIbng0MkdETnhWN2JGM3l1WUlIWlU0bk5XUGp0Tm9TY2ZGWW9tWVgzeUJWT0JXc3VJWUttWXZtZURYcndOdE1WNlh0Znc0S1hLeUV3TTNnSEtQWXhXYkFZNDR0aU84d2lJeTZWajBRUWd5TThBNnFYWTNhbHNvajVTVlVpUzF3RzZReTlNaTZyYmxMTWlTdnAzUk04ZFBmbWFaci1kNERwTnFRYUtTcjR3LXhrdlUtYXpaRjVKb0hhaXVBb0k2M1oyTXFmVWt3WUlmYmRkOVIxZ2xWMnRFbTlaYlBaTDBZaHBhX2NvNEtrQmpMQ2VmNHY4Sm83dHJDdktQRUQ4cDlnUUhzTGRMVUY3dWI0MFBPVlh1bFdxNzNFTmI4dGZPSklmdEt1bzJvVVhHbVJvZS02RkJRRnctOVRNbWp6Y0lzdGJ0WkVEMFpjWGNLbXNWUWJiVUNhQ180eGVCQlU0NjViTXJqWFlxYTNmMnB4TGlKREdiWER3b3J5S0N6UkNPcE05VEVLN1EwaUxVbkNMX3FXZldZNzJqQS56eDVScU5za3JZeGtpVUFJV3pPR3ZRIiwiYXR0ZXN0ZWRfa2V5cyI6W3siY3J2IjoiUC0yNTYiLCJ4IjoiRVA4NVRicHVvbGF4QS01SkxfSnk1clJsclN1dU9jV2NWYlV3Q0ZtT0QyZyIsImFsZyI6IkVTMjU2IiwidXNlIjoic2lnIiwia3R5IjoiRUMiLCJ5IjoiNTdpMll3UEo2VkhUUnFONEJVb3FZeFVxR25kNmZNYmRIRkd4R0ZOSmRZWSIsImtpZCI6IjM4MDhGQTIxLTUzQjEtNEIwNy1BRUJCLTAyRkNBRjY3MDdFMCJ9XSwiZXhwIjoxNzU5MzE4Mjk5LCJrZXlfc3RvcmFnZSI6WyJpc29fMTgwNDVfbW9kZXJhdGUiXSwidXNlcl9hdXRoZW50aWNhdGlvbiI6WyJpc29fMTgwNDVfbW9kZXJhdGUiXX0.EJpJkRimn38NxLuCDfgBM8isImqicUREN8AWIC9yZ6oYCOohoprLxacfufw2Iya3j6JfCpHLPUCTz-Ff9CN6DQ"
  
  static let keyAttestationInvalidJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"
  
  static let signedMetadataJWK: ECPublicKey = .init(
    crv: .P256,
    x: "ilzt0a_ukEX-nl0S05S2RAlbQFL2DSOpTjT3xf52JBY",
    y: "q-fNv_d0nlZf_S_3S-KmrktIsylB0cybRiL6rZMLZHI"
  )
  
  static let keyAttestationPrivateKey = createECPrivateSecKey(
    xStr: "EP85TbpuolaxA-5JL_Jy5rRlrSuuOcWcVbUwCFmOD2g",
    yStr: "57i2YwPJ6VHTRqN4BUoqYxUqGnd6fMbdHFGxGFNJdYY",
    dStr: "pVSBXMFGpWsW_FKIEsOp-tTnvheTdadCueGPMjAEciQ"
  )!
  
  static let keyAttestationCertificate = "MIIBXDCCAQKgAwIBAgIUWehiP2nqV9QcfFSEW+MBmFVPSqgwCgYIKoZIzj0EAwIwLjELMAkGA1UEBhMCVVQxHzAdBgNVBAMMFmtleS1hdHRlc3RhdGlvbi1pc3N1ZXIwHhcNMjUwNzI5MDgzMTU2WhcNMjYwNzI5MDgzMTU2WjAuMQswCQYDVQQGEwJVVDEfMB0GA1UEAwwWa2V5LWF0dGVzdGF0aW9uLWlzc3VlcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBD/OU26bqJWsQPuSS/ycua0Za0rrjnFnFW1MAhZjg9o57i2YwPJ6VHTRqN4BUoqYxUqGnd6fMbdHFGxGFNJdYYwCgYIKoZIzj0EAwIDSAAwRQIhALqh3nRBGeb4YP0MgnwiDK15RdGx8qgK143FAIPTygpIAiARQtRHbFI4MFwajzUYLrZrMUZUURb+lDvLn4rojCUN5w=="
  
  static func keyAttestationJWT(_ nonce: String?, _ proxy: SigningKeyProxy, _ jwk: JWK, _ cert: String) async throws -> KeyAttestationJWT {
    let duration: TimeInterval = 300.0
    let now = Int(Date().timeIntervalSince1970)
    let exp = Int(Date().addingTimeInterval(duration).timeIntervalSince1970)
    var payloadDictionary = [
      "attested_keys": [
        try jwk.toDictionary()
      ],
      "exp": exp,
      "iat": now,
      "key_storage": [
        "iso_18045_moderate"
      ],
      "user_authentication": [
        "iso_18045_moderate"
      ]
    ] as [String : Any]
    
    if let nonce {
      payloadDictionary["nonce"] = nonce
    }
    
    let header: JWSHeader = try .init(parameters: [
      "alg": "ES256",
      "typ": KeyAttestationJWT.keyAttestationJWTType,
      "x5c": [
        cert
      ]
    ])
    let payload = Payload(try payloadDictionary.toThrowingJSONData())
    
    let keyAttestationJWS: JWS = try! .init(
      header: header,
      payload: payload,
      signer: await BindingKey.createSigner(
        with: header,
        and: payload,
        for: proxy,
        and: .ES256
      )
    )
    return try .init(jws: keyAttestationJWS)
  }
}

final class TestSinger: AsyncSignerProtocol {
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

final class AsyncSigner: AsyncSignerProtocol {
  let signer: Signer
  
  init(signer: Signer) {
    self.signer = signer
  }
  
  func signAsync(_ header: Data, _ payload: Data) async throws -> Data {
    
    guard
      let jwsHeader = JWSHeader(header)
    else {
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
      signer: self.signer
    )
    
    return jws.signature
  }
}

let ISSUANCE_MESSAGE = "--> [ISSUANCE] Issued credentials:"
let OFFER_BASED_SCENARIO = "[[Scenario: Offer passed to wallet via url]] "
let NO_OFFER_BASED_SCENARIO = "[[Scenario: No offer passed, wallet initiates issuance by credetial scopes]]"

func createECPrivateSecKey(xStr: String, yStr: String, dStr: String) -> SecKey? {
  // Fix padding for Base64URL → Base64
  func fixBase64Padding(_ base64url: String) -> String {
    var base64 = base64url
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let padding = base64.count % 4
    if padding == 2 {
      base64.append("==")
    } else if padding == 3 {
      base64.append("=")
    } else if padding == 1 {
      base64.append("===") // rare case
    }
    return base64
  }
  
  // Decode base64URL strings
  guard let xBytes = Data(base64Encoded: fixBase64Padding(xStr)),
        let yBytes = Data(base64Encoded: fixBase64Padding(yStr)),
        let dBytes = Data(base64Encoded: fixBase64Padding(dStr)) else {
    print("❌ Base64 decoding failed")
    return nil
  }
  
  // Create uncompressed public key format: 0x04 || x || y
  let keyData = NSMutableData(bytes: [0x04], length: 1)
  keyData.append(xBytes)
  keyData.append(yBytes)
  
  // This is just the public key part, but you want a private key, so dBytes must be included in the right format.
  // Append private key d — this by itself doesn't make a valid private key structure,
  // but we are assuming your environment accepts raw private key with appended dBytes.
  keyData.append(dBytes)
  
  // Attributes
  let attributes: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrIsPermanent as String: false
  ]
  
  // Create SecKey
  var error: Unmanaged<CFError>?
  guard let keyReference = SecKeyCreateWithData(keyData as CFData,
                                                attributes as CFDictionary,
                                                &error) else {
    print("❌ SecKeyCreateWithData failed:", error!.takeRetainedValue())
    return nil
  }
  
  return keyReference
}

func testEncryptionSpec() -> EncryptionSpec? {
  
  func dictionaryToData(_ dict: [String: any Sendable]) throws -> Data {
    // Convert values that might be SwiftyJSON.JSON into plain `Any`
    let normalized = dict.mapValues { value -> Any in
      if let jsonValue = value as? JSON {
        return jsonValue.object   // get raw object from SwiftyJSON
      }
      return value
    }
    
    // Ensure the result is valid JSON
    guard JSONSerialization.isValidJSONObject(normalized) else {
      throw NSError(
        domain: "DictionaryToDataError",
        code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Dictionary is not a valid JSON object"]
      )
    }
    
    return try JSONSerialization.data(withJSONObject: normalized, options: [])
  }
  
  return try! .init(
    recipientKey: try! ECPublicKey(data: try! dictionaryToData([
      "kty": "EC",
      "use": "enc",
      "crv": "P-256",
      "kid": "d3102833-700c-42fe-979b-4880ba88ee22",
      "x": "9Yx_0Huh1XTF6hUScqikf07674hci1McgQqK5NwTDLg",
      "y": "JGcPMr7d1_KLTm5euw7EolLYsU4J2pg-2tC_xrTjFaQ",
      "alg": "ECDH-ES"
    ])),
    encryptionMethod: .init(.A128GCM)
  )
}

@globalActor
actor KeyAttester {
  static let shared = KeyAttester()
}
