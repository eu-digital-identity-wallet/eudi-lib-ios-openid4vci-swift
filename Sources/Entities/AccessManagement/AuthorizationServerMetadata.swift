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

public struct AuthorizationServerMetadata: Codable, Equatable {
  public let issuer, authorizationEndpoint, tokenEndpoint, introspectionEndpoint: String?
  public let jwksURI: String?
  public let grantTypesSupported, responseTypesSupported, requestObjectSigningAlgValuesSupported, requestObjectEncryptionAlgValuesSupported: [String]?
  public let requestObjectEncryptionEncValuesSupported, responseModesSupported: [String]?
  public let registrationEndpoint: String?
  public let tokenEndpointAuthMethodsSupported, tokenEndpointAuthSigningAlgValuesSupported, introspectionEndpointAuthMethodsSupported, introspectionEndpointAuthSigningAlgValuesSupported: [String]?
  public let authorizationSigningAlgValuesSupported, authorizationEncryptionAlgValuesSupported, authorizationEncryptionEncValuesSupported, scopesSupported: [String]?
  public let requestParameterSupported, requestURIParameterSupported, requireRequestURIRegistration: Bool?
  public let codeChallengeMethodsSupported: [String]?
  public let tlsClientCertificateBoundAccessTokens: Bool?
  public let dpopSigningAlgValuesSupported: [String]?
  public let revocationEndpoint: String?
  public let revocationEndpointAuthMethodsSupported, revocationEndpointAuthSigningAlgValuesSupported: [String]?
  public let deviceAuthorizationEndpoint: String?
  public let backchannelTokenDeliveryModesSupported: [String]?
  public let backchannelAuthenticationEndpoint: String?
  public let backchannelAuthenticationRequestSigningAlgValuesSupported: [String]?
  public let requirePushedAuthorizationRequests: Bool?
  public let pushedAuthorizationRequestEndpoint: String?
  public let mtlsEndpointAliases: MtlsEndpointAliases?
  public let authorizationResponseIssParameterSupported: Bool?
  
  enum CodingKeys: String, CodingKey {
    case issuer
    case authorizationEndpoint = "authorization_endpoint"
    case tokenEndpoint = "token_endpoint"
    case introspectionEndpoint = "introspection_endpoint"
    case jwksURI = "jwks_uri"
    case grantTypesSupported = "grant_types_supported"
    case responseTypesSupported = "response_types_supported"
    case requestObjectSigningAlgValuesSupported = "request_object_signing_alg_values_supported"
    case requestObjectEncryptionAlgValuesSupported = "request_object_encryption_alg_values_supported"
    case requestObjectEncryptionEncValuesSupported = "request_object_encryption_enc_values_supported"
    case responseModesSupported = "response_modes_supported"
    case registrationEndpoint = "registration_endpoint"
    case tokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported"
    case tokenEndpointAuthSigningAlgValuesSupported = "token_endpoint_auth_signing_alg_values_supported"
    case introspectionEndpointAuthMethodsSupported = "introspection_endpoint_auth_methods_supported"
    case introspectionEndpointAuthSigningAlgValuesSupported = "introspection_endpoint_auth_signing_alg_values_supported"
    case authorizationSigningAlgValuesSupported = "authorization_signing_alg_values_supported"
    case authorizationEncryptionAlgValuesSupported = "authorization_encryption_alg_values_supported"
    case authorizationEncryptionEncValuesSupported = "authorization_encryption_enc_values_supported"
    case scopesSupported = "scopes_supported"
    case requestParameterSupported = "request_parameter_supported"
    case requestURIParameterSupported = "request_uri_parameter_supported"
    case requireRequestURIRegistration = "require_request_uri_registration"
    case codeChallengeMethodsSupported = "code_challenge_methods_supported"
    case tlsClientCertificateBoundAccessTokens = "tls_client_certificate_bound_access_tokens"
    case dpopSigningAlgValuesSupported = "dpop_signing_alg_values_supported"
    case revocationEndpoint = "revocation_endpoint"
    case revocationEndpointAuthMethodsSupported = "revocation_endpoint_auth_methods_supported"
    case revocationEndpointAuthSigningAlgValuesSupported = "revocation_endpoint_auth_signing_alg_values_supported"
    case deviceAuthorizationEndpoint = "device_authorization_endpoint"
    case backchannelTokenDeliveryModesSupported = "backchannel_token_delivery_modes_supported"
    case backchannelAuthenticationEndpoint = "backchannel_authentication_endpoint"
    case backchannelAuthenticationRequestSigningAlgValuesSupported = "backchannel_authentication_request_signing_alg_values_supported"
    case requirePushedAuthorizationRequests = "require_pushed_authorization_requests"
    case pushedAuthorizationRequestEndpoint = "pushed_authorization_request_endpoint"
    case mtlsEndpointAliases = "mtls_endpoint_aliases"
    case authorizationResponseIssParameterSupported = "authorization_response_iss_parameter_supported"
  }
  
  public init(
    issuer: String?,
    authorizationEndpoint: String?,
    tokenEndpoint: String?,
    introspectionEndpoint: String?,
    jwksURI: String?,
    grantTypesSupported: [String]?,
    responseTypesSupported: [String]?,
    requestObjectSigningAlgValuesSupported: [String]?,
    requestObjectEncryptionAlgValuesSupported: [String]?,
    requestObjectEncryptionEncValuesSupported: [String]?,
    responseModesSupported: [String]?,
    registrationEndpoint: String?,
    tokenEndpointAuthMethodsSupported: [String]?,
    tokenEndpointAuthSigningAlgValuesSupported: [String]?,
    introspectionEndpointAuthMethodsSupported: [String]?,
    introspectionEndpointAuthSigningAlgValuesSupported: [String]?,
    authorizationSigningAlgValuesSupported: [String]?,
    authorizationEncryptionAlgValuesSupported: [String]?,
    authorizationEncryptionEncValuesSupported: [String]?,
    scopesSupported: [String]?,
    requestParameterSupported: Bool?,
    requestURIParameterSupported: Bool?,
    requireRequestURIRegistration: Bool?,
    codeChallengeMethodsSupported: [String]?,
    tlsClientCertificateBoundAccessTokens: Bool?,
    dpopSigningAlgValuesSupported: [String]?,
    revocationEndpoint: String?,
    revocationEndpointAuthMethodsSupported: [String]?,
    revocationEndpointAuthSigningAlgValuesSupported: [String]?,
    deviceAuthorizationEndpoint: String?,
    backchannelTokenDeliveryModesSupported: [String]?,
    backchannelAuthenticationEndpoint: String?,
    backchannelAuthenticationRequestSigningAlgValuesSupported: [String]?,
    requirePushedAuthorizationRequests: Bool?,
    pushedAuthorizationRequestEndpoint: String?,
    mtlsEndpointAliases: MtlsEndpointAliases?,
    authorizationResponseIssParameterSupported: Bool?
  ) {
    self.issuer = issuer
    self.authorizationEndpoint = authorizationEndpoint
    self.tokenEndpoint = tokenEndpoint
    self.introspectionEndpoint = introspectionEndpoint
    self.jwksURI = jwksURI
    self.grantTypesSupported = grantTypesSupported
    self.responseTypesSupported = responseTypesSupported
    self.requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported
    self.requestObjectEncryptionAlgValuesSupported = requestObjectEncryptionAlgValuesSupported
    self.requestObjectEncryptionEncValuesSupported = requestObjectEncryptionEncValuesSupported
    self.responseModesSupported = responseModesSupported
    self.registrationEndpoint = registrationEndpoint
    self.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported
    self.tokenEndpointAuthSigningAlgValuesSupported = tokenEndpointAuthSigningAlgValuesSupported
    self.introspectionEndpointAuthMethodsSupported = introspectionEndpointAuthMethodsSupported
    self.introspectionEndpointAuthSigningAlgValuesSupported = introspectionEndpointAuthSigningAlgValuesSupported
    self.authorizationSigningAlgValuesSupported = authorizationSigningAlgValuesSupported
    self.authorizationEncryptionAlgValuesSupported = authorizationEncryptionAlgValuesSupported
    self.authorizationEncryptionEncValuesSupported = authorizationEncryptionEncValuesSupported
    self.scopesSupported = scopesSupported
    self.requestParameterSupported = requestParameterSupported
    self.requestURIParameterSupported = requestURIParameterSupported
    self.requireRequestURIRegistration = requireRequestURIRegistration
    self.codeChallengeMethodsSupported = codeChallengeMethodsSupported
    self.tlsClientCertificateBoundAccessTokens = tlsClientCertificateBoundAccessTokens
    self.dpopSigningAlgValuesSupported = dpopSigningAlgValuesSupported
    self.revocationEndpoint = revocationEndpoint
    self.revocationEndpointAuthMethodsSupported = revocationEndpointAuthMethodsSupported
    self.revocationEndpointAuthSigningAlgValuesSupported = revocationEndpointAuthSigningAlgValuesSupported
    self.deviceAuthorizationEndpoint = deviceAuthorizationEndpoint
    self.backchannelTokenDeliveryModesSupported = backchannelTokenDeliveryModesSupported
    self.backchannelAuthenticationEndpoint = backchannelAuthenticationEndpoint
    self.backchannelAuthenticationRequestSigningAlgValuesSupported = backchannelAuthenticationRequestSigningAlgValuesSupported
    self.requirePushedAuthorizationRequests = requirePushedAuthorizationRequests
    self.pushedAuthorizationRequestEndpoint = pushedAuthorizationRequestEndpoint
    self.mtlsEndpointAliases = mtlsEndpointAliases
    self.authorizationResponseIssParameterSupported = authorizationResponseIssParameterSupported
  }
  public static func == (lhs: AuthorizationServerMetadata, rhs: AuthorizationServerMetadata) -> Bool {
    lhs.authorizationEndpoint == rhs.authorizationEndpoint
  }
}
