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

/// Configuration options for issuance.
public enum AuthorizeIssuanceConfig: Sendable {
  /// Favor the use of scopes.
  case favorScopes
  /// Use authorization details instead of scopes.
  case authorizationDetails
}

/// How the Authorization Code is bound to the DPoP key, per RFC 9449 §10.1.
public enum AuthorizationCodeDPoPBindingMethod: Sendable, Equatable {
  /// The Authorization Code is not bound to the DPoP key.
  case none

  /// Bind the Authorization Code to the DPoP key by attaching a DPoP proof in the `DPoP` header
  /// of the PAR request. This method requires the use of PAR; without PAR the DPoP header cannot
  /// be used, so the binding falls back to `dpopJkt`.
  case dpopHeader

  /// Bind the Authorization Code to the DPoP key by including the `dpop_jkt` parameter
  /// (the RFC 7638 JWK thumbprint of the DPoP public key) in the PAR request body when PAR
  /// is used, or in the authorization request when PAR is not used.
  case dpopJkt
}

/// Configuration for Pushed Authorization Request (PAR) usage.
///
/// How the Authorization Code is bound to the DPoP key (if at all) is configured separately via
/// `AuthorizationCodeGrant.authorizationCodeDPoPBindingMethod`, per RFC 9449 §10.1.
public enum ParUsage: Sendable, Equatable {
  /// Disables PAR. Wallet will use the usual authorization code flow.
  case never

  /// If authorization server advertises PAR endpoint it will be used.
  /// Otherwise, falls back to usual authorization code flow.
  case ifSupported

  /// Wallet always will place PAR request, regardless of whether authorization server
  /// advertises the PAR endpoint. If PAR endpoint is not being advertised, issuance fails.
  case required
}

/// Wallet's policy in regard to validating the `iss` parameter present in the authorization response
/// as described by the Authorization Server metadata field
/// `authorization_response_iss_parameter_supported`.
///
/// The `iss` parameter is used to mitigate mix-up attacks, by allowing the Wallet to verify that the
/// authorization response was issued by the expected Authorization Server.
public enum AuthorizationResponseIssChecking: Sendable {
  /// The Wallet never validates the `iss` parameter of the authorization response.
  case never
  /// The Wallet validates the `iss` parameter only when the Authorization Server
  /// advertises support for it.
  case ifSupported
  /// The Wallet requires the Authorization Server to support the `iss` parameter.
  /// If the Authorization Server does not advertise support, issuance fails.
  case required
}

/// Configuration for the Authorization Code grant type.
public struct AuthorizationCodeGrant: Sendable, Equatable {
  /// The redirect URI to be passed as the `redirect_uri` parameter of the authorization request.
  public let authFlowRedirectionURI: URL

  /// The wallet's policy regarding the use of the PAR endpoint.
  public let parUsage: ParUsage

  /// How the Authorization Code is bound to the DPoP key, per RFC 9449 §10.1.
  public let authorizationCodeDPoPBindingMethod: AuthorizationCodeDPoPBindingMethod

  public init(
    authFlowRedirectionURI: URL,
    parUsage: ParUsage = .ifSupported,
    authorizationCodeDPoPBindingMethod: AuthorizationCodeDPoPBindingMethod = .dpopHeader
  ) {
    self.authFlowRedirectionURI = authFlowRedirectionURI
    self.parUsage = parUsage
    self.authorizationCodeDPoPBindingMethod = authorizationCodeDPoPBindingMethod
  }
}

/// A type alias representing a Client ID.
public typealias ClientId = String

/// A type alias representing a Client Secret.
public typealias ClientSecret = String

/// Configuration for OpenID4VCI.
public struct OpenId4VCIConfig: Sendable {

  /// The client used for OpenID4VCI operations.
  public let client: Client

  /// Configuration specifying how issuance authorization should be handled.
  public let authorizeIssuanceConfig: AuthorizeIssuanceConfig

  /// An optional builder for client attestation proof-of-possession tokens.
  public let clientAttestationPoPBuilder: ClientAttestationPoPBuilder?

  /// Policy defining how issuer metadata should be handled.
  public let issuerMetadataPolicy: IssuerMetadataPolicy

  /// Client supported compression algorithms
  public let supportedCompressionAlgorithms: [CompressionAlgorithm]?

  /// Dpop requirement, if required by wallet and not supported by issuer, halt the issuance process
  public let requireDpop: Bool

  /// When `true`, the wallet insists on presenting a client-attestation PoP JWT on every
  /// authorization-server exchange that supports it.
  public let requireClientAttestation: Bool

  /// Wallet's supported credential reuse policies
  public let supportedCredentialReusePolicies: SupportedCredentialReusePolicies

  /// Policy defining which signing algorithms and attested proof types the
  /// wallet supports. Plain `jwt` proofs (no key attestation) are not supported.
  ///
  /// Default is `.haipCompliant()`.
  public let proofTypesPolicy: ProofTypesPolicy

  /// Optional policy that, when set, activates WRP Registration Certificate (WRPRC)
  /// enforcement during `Issuer.make(...)`. When `nil`, WRPRC is not validated.
  public let registrationCertificatePolicy: RegistrationCertificatePolicy?

  /// The grant types supported by the wallet.
  public let supportedGrants: SupportedGrants

  /// Wallet-side configuration of credential request / response encryption: whether encrypted
  /// responses are required, which key families (EC / RSA), curve, key size, algorithms and
  /// content encryption methods the wallet is willing to use.
  ///
  /// Default is `.default` (encryption supported but not required, EC P-256 and RSA 2048).
  public let encryptionSupportConfig: EncryptionSupportConfig

  /// Wallet's policy concerning the validation of the `iss` parameter present in the
  /// authorization response (RFC 9207).
  ///
  /// Default is `.never`.
  public let authResponseIssChecking: AuthorizationResponseIssChecking

  // MARK: - Computed Properties (Backward Compatibility)

  /// The URI to which the authentication flow should redirect.
  /// Extracted from `supportedGrants.authorizationCodeGrant`.
  public var authFlowRedirectionURI: URL? {
    supportedGrants.authorizationCodeGrant?.authFlowRedirectionURI
  }

  /// The wallet's PAR usage policy.
  /// Extracted from `supportedGrants.authorizationCodeGrant`.
  public var parUsage: ParUsage {
    supportedGrants.authorizationCodeGrant?.parUsage ?? .never
  }

  /// The wallet's Authorization Code DPoP binding method.
  /// Extracted from `supportedGrants.authorizationCodeGrant`.
  public var authorizationCodeDPoPBindingMethod: AuthorizationCodeDPoPBindingMethod {
    supportedGrants.authorizationCodeGrant?.authorizationCodeDPoPBindingMethod ?? .none
  }

  // MARK: - Initializers

  /// Initializes an `OpenId4VCIConfig` instance with the new grant-based configuration.
  /// - Parameters:
  ///   - client: The client used for OpenID4VCI operations.
  ///   - authorizeIssuanceConfig: Specifies how issuance authorization should be handled (default: `.favorScopes`).
  ///   - clientAttestationPoPBuilder: An optional client attestation PoP builder (default: `nil`).
  ///   - issuerMetadataPolicy: Policy defining how issuer metadata should be handled (default: `.ignoreSigned`).
  ///   - supportedCompressionAlgorithms: Client supported compression algorithms (default: `nil`).
  ///   - proofTypesPolicy: Policy defining which proof types the wallet supports (default: `.haipCompliant()`).
  ///   - requireDpop: If dpop is supported then use it, otherwise always don't (default: `true`).
  ///   - requireClientAttestation: Whether to require client attestation (default: `false`).
  ///   - supportedCredentialReusePolicies: Wallet's supported credential reuse policies (default: `.notSupported`).
  ///   - registrationCertificatePolicy: Optional policy that activates WRPRC enforcement (default: `nil`).
  ///   - supportedGrants: The grant types supported by the wallet.
  ///   - encryptionSupportConfig: Wallet-side request/response encryption configuration (default: `.default`).
  ///   - authResponseIssChecking: Wallet's policy concerning the validation of the `iss` parameter (default: `.never`).
  public init(
    client: Client,
    authorizeIssuanceConfig: AuthorizeIssuanceConfig = .favorScopes,
    clientAttestationPoPBuilder: ClientAttestationPoPBuilder? = nil,
    issuerMetadataPolicy: IssuerMetadataPolicy = .ignoreSigned,
    supportedCompressionAlgorithms: [CompressionAlgorithm]? = nil,
    proofTypesPolicy: ProofTypesPolicy = .haipCompliant(),
    requireDpop: Bool = true,
    requireClientAttestation: Bool = false,
    supportedCredentialReusePolicies: SupportedCredentialReusePolicies = .notSupported,
    registrationCertificatePolicy: RegistrationCertificatePolicy? = nil,
    supportedGrants: SupportedGrants,
    encryptionSupportConfig: EncryptionSupportConfig = .default,
    authResponseIssChecking: AuthorizationResponseIssChecking = .never
  ) {
    // When a WRPRC policy is configured, the issuer metadata must be signed
    if registrationCertificatePolicy != nil {
      switch issuerMetadataPolicy {
      case .requireSigned:
        break
      case .preferSigned, .ignoreSigned:
        preconditionFailure(
          "OpenId4VCIConfig: registrationCertificatePolicy requires " +
          "issuerMetadataPolicy = .requireSigned(...). " +
          "Received: \(issuerMetadataPolicy)"
        )
      }
    }

    self.client = client
    self.authorizeIssuanceConfig = authorizeIssuanceConfig
    self.clientAttestationPoPBuilder = clientAttestationPoPBuilder
    self.issuerMetadataPolicy = issuerMetadataPolicy
    self.supportedCompressionAlgorithms = supportedCompressionAlgorithms
    self.requireDpop = requireDpop
    self.requireClientAttestation = requireClientAttestation
    self.supportedCredentialReusePolicies = supportedCredentialReusePolicies
    self.proofTypesPolicy = proofTypesPolicy
    self.registrationCertificatePolicy = registrationCertificatePolicy
    self.supportedGrants = supportedGrants
    self.encryptionSupportConfig = encryptionSupportConfig
    self.authResponseIssChecking = authResponseIssChecking
  }

  /// Legacy initializer for backward compatibility.
  /// - Parameters:
  ///   - client: The client used for OpenID4VCI operations.
  ///   - authFlowRedirectionURI: The URI to which the authentication flow should redirect.
  ///   - authorizeIssuanceConfig: Specifies how issuance authorization should be handled.
  ///   - parUsage: The wallet's PAR usage policy.
  ///   - authorizationCodeDPoPBindingMethod: How the Authorization Code is bound to the DPoP key.
  ///   - clientAttestationPoPBuilder: An optional client attestation PoP builder.
  ///   - issuerMetadataPolicy: Policy defining how issuer metadata should be handled.
  ///   - supportedCompressionAlgorithms: Client supported compression algorithms.
  ///   - proofTypesPolicy: Policy defining which proof types the wallet supports.
  ///   - requireDpop: If dpop is required by wallet.
  ///   - requireClientAttestation: Whether to require client attestation.
  ///   - supportedCredentialReusePolicies: Wallet's supported credential reuse policies.
  ///   - registrationCertificatePolicy: Optional policy that activates WRPRC enforcement.
  ///   - encryptionSupportConfig: Wallet-side request/response encryption configuration.
  ///   - authResponseIssChecking: Wallet's policy concerning the validation of the `iss` parameter.
  public init(
    client: Client,
    authFlowRedirectionURI: URL,
    authorizeIssuanceConfig: AuthorizeIssuanceConfig = .favorScopes,
    parUsage: ParUsage = .required,
    authorizationCodeDPoPBindingMethod: AuthorizationCodeDPoPBindingMethod = .dpopHeader,
    clientAttestationPoPBuilder: ClientAttestationPoPBuilder? = nil,
    issuerMetadataPolicy: IssuerMetadataPolicy = .ignoreSigned,
    supportedCompressionAlgorithms: [CompressionAlgorithm]? = nil,
    proofTypesPolicy: ProofTypesPolicy = .haipCompliant(),
    requireDpop: Bool = true,
    requireClientAttestation: Bool = false,
    supportedCredentialReusePolicies: SupportedCredentialReusePolicies = .notSupported,
    registrationCertificatePolicy: RegistrationCertificatePolicy? = nil,
    encryptionSupportConfig: EncryptionSupportConfig = .default,
    authResponseIssChecking: AuthorizationResponseIssChecking = .never
  ) {
    let authCodeGrant = AuthorizationCodeGrant(
      authFlowRedirectionURI: authFlowRedirectionURI,
      parUsage: parUsage,
      authorizationCodeDPoPBindingMethod: authorizationCodeDPoPBindingMethod
    )

    self.init(
      client: client,
      authorizeIssuanceConfig: authorizeIssuanceConfig,
      clientAttestationPoPBuilder: clientAttestationPoPBuilder,
      issuerMetadataPolicy: issuerMetadataPolicy,
      supportedCompressionAlgorithms: supportedCompressionAlgorithms,
      proofTypesPolicy: proofTypesPolicy,
      requireDpop: requireDpop,
      requireClientAttestation: requireClientAttestation,
      supportedCredentialReusePolicies: supportedCredentialReusePolicies,
      registrationCertificatePolicy: registrationCertificatePolicy,
      supportedGrants: .both(authorizationCode: authCodeGrant),
      encryptionSupportConfig: encryptionSupportConfig,
      authResponseIssChecking: authResponseIssChecking
    )
  }
}
