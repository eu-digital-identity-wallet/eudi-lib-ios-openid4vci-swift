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
  public let issuer: String?
  public let jwksUri: String?
  public let scopesSupported: Bool?
  public let responseTypesSupported: Bool?
  public let responseModesSupported: Bool?
  public let grantTypesSupported: Bool?
  public let codeChallengeMethodsSupported: Bool?
  public let tokenEndpointAuthMethodsSupported: Bool?
  public let tokenEndpointAuthSigningAlgValuesSupported: Bool?
  public let requestParameterSupported: Bool?
  public let requestUriParameterSupported: Bool?
  public let requireRequestUriRegistration: Bool?
  public let requestObjectSigningAlgValuesSupported: Bool?
  public let requestObjectEncryptionAlgValuesSupported: Bool?
  public let requestObjectEncryptionEncValuesSupported: Bool?
  public let uiLocalesSupported: Bool?
  public let serviceDocumentation: String?
  public let opPolicyUri: String?
  public let opTosUri: String?
  public let introspectionEndpointAuthMethodsSupported: Bool?
  public let introspectionEndpointAuthSigningAlgValuesSupported: Bool?
  public let revocationEndpointAuthMethodsSupported: Bool?
  public let revocationEndpointAuthSigningAlgValuesSupported: Bool?
  public let mtlsEndpointAliases: Bool?
  public let tlsClientCertificateBoundAccessTokens: Bool?
  public let dpopSigningAlgValuesSupported: Bool?
  public let authorizationSigningAlgValuesSupported: Bool?
  public let authorizationEncryptionAlgValuesSupported: Bool?
  public let authorizationEncryptionEncValuesSupported: Bool?
  public let requirePushedAuthorizationRequests: Bool?
  public let authorizationDetailsTypesSupported: Bool?
  public let incrementalAuthzTypesSupported: Bool?
  public let authorizationResponseIssParameterSupported: Bool?
  public let backchannelTokenDeliveryModesSupported: Bool?
  public let backchannelAuthenticationRequestSigningAlgValuesSupported: Bool?
  public let backchannelUserCodeParameterSupported: Bool?
  public let promptValuesSupported: Bool?
  public let organizationName: String?
  public let jwks: String?
  public let signedJwksUri: String?
  public let clientRegistrationTypesSupported: Bool?
  public let requestAuthenticationMethodsSupported: Bool?
  public let requestAuthenticationSigningAlgValuesSupported: Bool?
  public let federationRegistrationEndpoint: String?
  
  enum CodingKeys: String, CodingKey {
    case issuer = "issuer"
    case jwksUri = "jwks_uri"
    case scopesSupported = "scopes_supported"
    case responseTypesSupported = "response_types_supported"
    case responseModesSupported = "response_modes_supported"
    case grantTypesSupported = "grant_types_supported"
    case codeChallengeMethodsSupported = "code_challenge_methods_supported"
    case tokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported"
    case tokenEndpointAuthSigningAlgValuesSupported = "token_endpoint_auth_signing_alg_values_supported"
    case requestParameterSupported = "request_parameter_supported"
    case requestUriParameterSupported = "request_uri_parameter_supported"
    case requireRequestUriRegistration = "require_request_uri_registration"
    case requestObjectSigningAlgValuesSupported = "request_object_signing_alg_values_supported"
    case requestObjectEncryptionAlgValuesSupported = "request_object_encryption_alg_values_supported"
    case requestObjectEncryptionEncValuesSupported = "request_object_encryption_enc_values_supported"
    case uiLocalesSupported = "ui_locales_supported"
    case serviceDocumentation = "service_documentation"
    case opPolicyUri = "op_policy_uri"
    case opTosUri = "op_tos_uri"
    case introspectionEndpointAuthMethodsSupported = "introspection_endpoint_auth_methods_supported"
    case introspectionEndpointAuthSigningAlgValuesSupported = "introspection_endpoint_auth_signing_alg_values_supported"
    case revocationEndpointAuthMethodsSupported = "revocation_endpoint_auth_methods_supported"
    case revocationEndpointAuthSigningAlgValuesSupported = "revocation_endpoint_auth_signing_alg_values_supported"
    case mtlsEndpointAliases = "mtls_endpoint_aliases"
    case tlsClientCertificateBoundAccessTokens = "tls_client_certificate_bound_access_tokens"
    case dpopSigningAlgValuesSupported = "dpop_signing_alg_values_supported"
    case authorizationSigningAlgValuesSupported = "authorization_signing_alg_values_supported"
    case authorizationEncryptionAlgValuesSupported = "authorization_encryption_alg_values_supported"
    case authorizationEncryptionEncValuesSupported = "authorization_encryption_enc_values_supported"
    case requirePushedAuthorizationRequests = "require_pushed_authorization_requests"
    case authorizationDetailsTypesSupported = "authorization_details_types_supported"
    case incrementalAuthzTypesSupported = "incremental_authz_types_supported"
    case authorizationResponseIssParameterSupported = "authorization_response_iss_parameter_supported"
    case backchannelTokenDeliveryModesSupported = "backchannel_token_delivery_modes_supported"
    case backchannelAuthenticationRequestSigningAlgValuesSupported = "backchannel_authentication_request_signing_alg_values_supported"
    case backchannelUserCodeParameterSupported = "backchannel_user_code_parameter_supported"
    case promptValuesSupported = "prompt_values_supported"
    case organizationName = "organization_name"
    case jwks = "jwks"
    case signedJwksUri = "signed_jwks_uri"
    case clientRegistrationTypesSupported = "client_registration_types_supported"
    case requestAuthenticationMethodsSupported = "request_authentication_methods_supported"
    case requestAuthenticationSigningAlgValuesSupported = "request_authentication_signing_alg_values_supported"
    case federationRegistrationEndpoint = "federation_registration_endpoint"
  }
  
  init(issuer: String?, jwksUri: String?, scopesSupported: Bool?, responseTypesSupported: Bool?, responseModesSupported: Bool?, grantTypesSupported: Bool?, codeChallengeMethodsSupported: Bool?, tokenEndpointAuthMethodsSupported: Bool?, tokenEndpointAuthSigningAlgValuesSupported: Bool?, requestParameterSupported: Bool?, requestUriParameterSupported: Bool?, requireRequestUriRegistration: Bool?, requestObjectSigningAlgValuesSupported: Bool?, requestObjectEncryptionAlgValuesSupported: Bool?, requestObjectEncryptionEncValuesSupported: Bool?, uiLocalesSupported: Bool?, serviceDocumentation: String?, opPolicyUri: String?, opTosUri: String?, introspectionEndpointAuthMethodsSupported: Bool?, introspectionEndpointAuthSigningAlgValuesSupported: Bool?, revocationEndpointAuthMethodsSupported: Bool?, revocationEndpointAuthSigningAlgValuesSupported: Bool?, mtlsEndpointAliases: Bool?, tlsClientCertificateBoundAccessTokens: Bool?, dpopSigningAlgValuesSupported: Bool?, authorizationSigningAlgValuesSupported: Bool?, authorizationEncryptionAlgValuesSupported: Bool?, authorizationEncryptionEncValuesSupported: Bool?, requirePushedAuthorizationRequests: Bool?, authorizationDetailsTypesSupported: Bool?, incrementalAuthzTypesSupported: Bool?, authorizationResponseIssParameterSupported: Bool?, backchannelTokenDeliveryModesSupported: Bool?, backchannelAuthenticationRequestSigningAlgValuesSupported: Bool?, backchannelUserCodeParameterSupported: Bool?, promptValuesSupported: Bool?, organizationName: String?, jwks: String?, signedJwksUri: String?, clientRegistrationTypesSupported: Bool?, requestAuthenticationMethodsSupported: Bool?, requestAuthenticationSigningAlgValuesSupported: Bool?, federationRegistrationEndpoint: String?) {
    self.issuer = issuer
    self.jwksUri = jwksUri
    self.scopesSupported = scopesSupported
    self.responseTypesSupported = responseTypesSupported
    self.responseModesSupported = responseModesSupported
    self.grantTypesSupported = grantTypesSupported
    self.codeChallengeMethodsSupported = codeChallengeMethodsSupported
    self.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported
    self.tokenEndpointAuthSigningAlgValuesSupported = tokenEndpointAuthSigningAlgValuesSupported
    self.requestParameterSupported = requestParameterSupported
    self.requestUriParameterSupported = requestUriParameterSupported
    self.requireRequestUriRegistration = requireRequestUriRegistration
    self.requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported
    self.requestObjectEncryptionAlgValuesSupported = requestObjectEncryptionAlgValuesSupported
    self.requestObjectEncryptionEncValuesSupported = requestObjectEncryptionEncValuesSupported
    self.uiLocalesSupported = uiLocalesSupported
    self.serviceDocumentation = serviceDocumentation
    self.opPolicyUri = opPolicyUri
    self.opTosUri = opTosUri
    self.introspectionEndpointAuthMethodsSupported = introspectionEndpointAuthMethodsSupported
    self.introspectionEndpointAuthSigningAlgValuesSupported = introspectionEndpointAuthSigningAlgValuesSupported
    self.revocationEndpointAuthMethodsSupported = revocationEndpointAuthMethodsSupported
    self.revocationEndpointAuthSigningAlgValuesSupported = revocationEndpointAuthSigningAlgValuesSupported
    self.mtlsEndpointAliases = mtlsEndpointAliases
    self.tlsClientCertificateBoundAccessTokens = tlsClientCertificateBoundAccessTokens
    self.dpopSigningAlgValuesSupported = dpopSigningAlgValuesSupported
    self.authorizationSigningAlgValuesSupported = authorizationSigningAlgValuesSupported
    self.authorizationEncryptionAlgValuesSupported = authorizationEncryptionAlgValuesSupported
    self.authorizationEncryptionEncValuesSupported = authorizationEncryptionEncValuesSupported
    self.requirePushedAuthorizationRequests = requirePushedAuthorizationRequests
    self.authorizationDetailsTypesSupported = authorizationDetailsTypesSupported
    self.incrementalAuthzTypesSupported = incrementalAuthzTypesSupported
    self.authorizationResponseIssParameterSupported = authorizationResponseIssParameterSupported
    self.backchannelTokenDeliveryModesSupported = backchannelTokenDeliveryModesSupported
    self.backchannelAuthenticationRequestSigningAlgValuesSupported = backchannelAuthenticationRequestSigningAlgValuesSupported
    self.backchannelUserCodeParameterSupported = backchannelUserCodeParameterSupported
    self.promptValuesSupported = promptValuesSupported
    self.organizationName = organizationName
    self.jwks = jwks
    self.signedJwksUri = signedJwksUri
    self.clientRegistrationTypesSupported = clientRegistrationTypesSupported
    self.requestAuthenticationMethodsSupported = requestAuthenticationMethodsSupported
    self.requestAuthenticationSigningAlgValuesSupported = requestAuthenticationSigningAlgValuesSupported
    self.federationRegistrationEndpoint = federationRegistrationEndpoint
  }
}
