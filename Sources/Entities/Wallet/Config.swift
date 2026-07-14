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

/// Configuration options for PAR usage.
public enum ParUsage: Sendable {
  case never
  case required(authorizationCodeDPoPBinding: Bool)
  
  public var required: Bool {
    switch self {
    case .never:
      false
    case .required:
      true
    }
  }
  
  public var authorizationCodeDPoPBinding: Bool {
    switch self {
    case .never:
      false
    case .required(let authorizationCodeDPoPBinding):
      authorizationCodeDPoPBinding
    }
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
  
  /// The URI to which the authentication flow should redirect.
  public let authFlowRedirectionURI: URL
  
  /// Configuration specifying how issuance authorization should be handled.
  public let authorizeIssuanceConfig: AuthorizeIssuanceConfig
  
  /// Whether to require PAR or not.
  public let requirePAR: ParUsage
  
  /// An optional builder for client attestation proof-of-possession tokens.
  public let clientAttestationPoPBuilder: ClientAttestationPoPBuilder?
  
  /// Policy defining how issuer metadata should be handled.
  public let issuerMetadataPolicy: IssuerMetadataPolicy
  
  /// Client supported compression algorithms
  public let supportedCompressionAlgorithms: [CompressionAlgorithm]?
  
  /// Dpop requirement, if required by wallet and not supported by issuer, halt the issuance process
  public let requireDpop: Bool
  
  /// Wallet's supported credential reuse policies
  public let supportedCredentialReusePolicies: SupportedCredentialReusePolicies
  
  /// Policy defining which signing algorithms and attested proof types the
  /// wallet supports. Plain `jwt` proofs (no key attestation) are not supported.
  ///
  /// Default is `.haipCompliant()`.
  public let proofTypesPolicy: ProofTypesPolicy
  
  /// Initializes an `OpenId4VCIConfig` instance with the given parameters.
  /// - Parameters:
  ///   - client: The client used for OpenID4VCI operations.
  ///   - authFlowRedirectionURI: The URI to which the authentication flow should redirect.
  ///   - authorizeIssuanceConfig: Specifies how issuance authorization should be handled (default: `.favorScopes`).
  ///   - requirePAR: Whether to require Pushed Authorization Requests (default: `true`).
  ///   - clientAttestationPoPBuilder: An optional client attestation PoP builder (default: `nil`).
  ///   - issuerMetadataPolicy: Policy defining how issuer metadata should be handled (default: `.ignoreSigned`).
  ///   - requireDpop: If dpop is supported then use it, otherwise always don't
  ///   - proofTypesPolicy: Policy defining which proof types the wallet supports (default: `.haipCompliant()`).
  ///   - supportedCredentialReusePolicies: Wallet's supported credential reuse policies (default: `.notSupported`).
  public init(
    client: Client,
    authFlowRedirectionURI: URL,
    authorizeIssuanceConfig: AuthorizeIssuanceConfig = .favorScopes,
    requirePAR: ParUsage = .required(authorizationCodeDPoPBinding: true),
    clientAttestationPoPBuilder: ClientAttestationPoPBuilder? = nil,
    issuerMetadataPolicy: IssuerMetadataPolicy = .ignoreSigned,
    supportedCompressionAlgorithms: [CompressionAlgorithm]? = nil,
    proofTypesPolicy: ProofTypesPolicy = .haipCompliant(),
    requireDpop: Bool = true,
    supportedCredentialReusePolicies: SupportedCredentialReusePolicies = .notSupported
  ) {
    self.client = client
    self.authFlowRedirectionURI = authFlowRedirectionURI
    self.authorizeIssuanceConfig = authorizeIssuanceConfig
    self.requirePAR = requirePAR
    self.clientAttestationPoPBuilder = clientAttestationPoPBuilder
    self.issuerMetadataPolicy = issuerMetadataPolicy
    self.supportedCompressionAlgorithms = supportedCompressionAlgorithms
    self.requireDpop = requireDpop
    self.supportedCredentialReusePolicies = supportedCredentialReusePolicies
    self.proofTypesPolicy = proofTypesPolicy
  }
}
