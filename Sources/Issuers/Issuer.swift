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

/// A protocol defining the operations required for an issuer in the credential issuance process.
public protocol IssuerType: Sendable {
  
  /// Initiates an authorization request using a credential offer.
  ///
  /// - Parameter credentialOffer: The credential offer containing necessary details for authorization.
  /// - Returns: A result containing either an `UnauthorizedRequest` if the request is successful or an `Error` otherwise.
  func prepareAuthorizationRequest(
    credentialOffer: CredentialOffer
  ) async throws -> AuthorizationRequested
  
  /// Authorizes a request using a pre-authorization code.
  ///
  /// - Parameters:
  ///   - credentialOffer: The credential offer used for authorization.
  ///   - authorizationCode: The pre-authorization code provided by the issuer.
  ///   - client: The client making the authorization request.
  ///   - transactionCode: An optional transaction code, if applicable.
  ///   - authorizationDetailsInTokenRequest: Additional authorization details for the token request.
  /// - Returns: A result containing either an `AuthorizedRequest` if authorization succeeds or an `Error` otherwise.
  func authorizeWithPreAuthorizationCode(
    credentialOffer: CredentialOffer,
    authorizationCode: IssuanceAuthorization,
    client: Client,
    transactionCode: String?,
    authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest
  ) async throws -> AuthorizedRequest
  
  /// Completes the authorization process using an authorization code.
  ///
  /// - Parameters:
  ///   - authorizationCode: The unauthorized request containing the authorization code.
  ///   - authorizationDetailsInTokenRequest: Additional authorization details for the token request.
  /// - Returns: A result containing either an `AuthorizedRequest` if successful or an `Error` otherwise.
  func authorizeWithAuthorizationCode(
    serverState: String,
    request: AuthorizationRequested,
    authorizationCode: AuthorizationCode,
    authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest,
    grant: Grants
  ) async throws -> AuthorizedRequest
  
  /// Requests credential issuance after authorization.
  ///
  /// - Parameters:
  ///   - request: The authorized request to proceed with credential issuance.
  ///   - bindingKeys: A list of binding keys used for secure binding of the credential.
  ///   - requestPayload: The payload required for the credential issuance.
  ///   - responseEncryptionSpecProvider: A closure providing the encryption specifications for the response.
  /// - Returns: A result containing either a `SubmittedRequest` if successful or an `Error` otherwise.
  func requestCredential(
    request: AuthorizedRequest,
    bindingKeys: [BindingKey],
    requestPayload: IssuanceRequestPayload,
    responseEncryptionSpecProvider: @Sendable (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> SubmittedRequest
  
  /// Requests a deferred credential issuance.
  ///
  /// - Parameters:
  ///   - request: The authorized request for credential issuance.
  ///   - transactionId: The transaction ID associated with the request.
  ///   - dPopNonce: An optional nonce for DPoP security.
  /// - Returns: A result containing either a `DeferredCredentialIssuanceResponse` if successful or an `Error` otherwise.
  func requestDeferredCredential(
    request: AuthorizedRequest,
    transactionId: TransactionId,
    dPopNonce: Nonce?
  ) async throws -> DeferredCredentialIssuanceResponse
  
  /// Sends a notification related to the credential issuance process.
  ///
  /// - Parameters:
  ///   - authorizedRequest: The authorized request linked to the notification.
  ///   - notificationId: The ID of the notification.
  ///   - dPopNonce: An optional nonce for DPoP security.
  /// - Returns: A result containing either `Void` if successful or an `Error` otherwise.
  func notify(
    authorizedRequest: AuthorizedRequest,
    notificationId: NotificationObject,
    dPopNonce: Nonce?
  ) async throws
  
  /// Refreshes an authorized request.
  ///
  /// - Parameters:
  ///   - clientId: The ID of the client requesting a refresh.
  ///   - authorizedRequest: The existing authorized request to be refreshed.
  ///   - dPopNonce: An optional nonce for DPoP security.
  /// - Returns: A result containing either a new `AuthorizedRequest` if successful or an `Error` otherwise.
  func refresh(
    clientId: String,
    authorizedRequest: AuthorizedRequest,
    dPopNonce: Nonce?
  ) async throws -> AuthorizedRequest
  
  /// Refreshes an authorized request.
  ///
  /// - Parameters:
  ///   - clientId: The Client requesting a refresh.
  ///   - authorizedRequest: The existing authorized request to be refreshed.
  ///   - dPopNonce: An optional nonce for DPoP security.
  /// - Returns: A result containing either a new `AuthorizedRequest` if successful or an `Error` otherwise.
  func refresh(
    client: Client,
    authorizedRequest: AuthorizedRequest,
    dPopNonce: Nonce?
  ) async throws -> AuthorizedRequest
  
  /// Sets the deferred response encryption specification to be used for issuance responses.
  ///
  /// - Parameter deferredResponseEncryptionSpec:
  ///   The encryption specification that defines how deferred issuance responses
  ///   should be encrypted. Pass `nil` to clear the existing specification.
  func setDeferredResponseEncryptionSpec(
    _ deferredResponseEncryptionSpec: IssuanceResponseEncryptionSpec?
  ) async
}

public actor Issuer: IssuerType {
  
  public var deferredResponseEncryptionSpec: IssuanceResponseEncryptionSpec?
  
  public let authorizationServerMetadata: IdentityAndAccessManagementMetadata
  public let issuerMetadata: CredentialIssuerMetadata
  public let config: OpenId4VCIConfig
  
  private let authorizeIssuance: AuthorizeIssuanceType
  private let authorizer: AuthorizationServerClientType
  private let nonceEndpointClient: NonceEndpointClientType?
  private let issuanceRequester: IssuanceRequesterType
  private let deferredIssuanceRequester: IssuanceRequesterType
  private let notifyIssuer: NotifyIssuerType
  private let challenger: ChallengeEndpointClientType?
  
  func encryptionSpec() throws -> EncryptionSpec? {
    
    switch issuerMetadata.credentialRequestEncryption {
    case .notRequired(
      let jwks,
      let encryptionMethodsSupported,
      _ /// compressionMethods
    ):
      guard let jwk = jwks.first, let method = encryptionMethodsSupported.first else {
        return nil
      }
      return try .init(
        recipientKey: jwk,
        encryptionMethod: method
      )
      
    case .required(
      let jwks,
      let encryptionMethodsSupported,
      _ /// compressionMethods
    ):
      guard let jwk = jwks.first, let method = encryptionMethodsSupported.first else {
        return nil
      }
      return try .init(
        recipientKey: jwk,
        encryptionMethod: method
      )
    default:
      /// Not supported
      return nil
    }
  }
  
  public init(
    authorizationServerMetadata: IdentityAndAccessManagementMetadata,
    issuerMetadata: CredentialIssuerMetadata,
    config: OpenId4VCIConfig,
    dpopConstructor: DPoPConstructorType? = nil,
    session: Networking
  ) throws {
    self.authorizationServerMetadata = authorizationServerMetadata
    self.issuerMetadata = issuerMetadata
    self.config = config
    
    if let challengeEndpoint = authorizationServerMetadata.challengeEndpointURI {
      challenger = ChallengeEndpointClient(challengeEndpoint: challengeEndpoint)
    } else {
      challenger = nil
    }
    
    if config.requireDpop {
      guard let dpopAlgs = authorizationServerMetadata.dpopSigningAlgValuesSupported,
            !dpopAlgs.isEmpty else {
        throw ValidationError.dpopRequired
      }
    }
    
    authorizer = try AuthorizationServerClient(
      challenger: challenger,
      parPoster: Poster(session: session),
      tokenPoster: Poster(session: session),
      config: config,
      authorizationServerMetadata: authorizationServerMetadata,
      credentialIssuerIdentifier: issuerMetadata.credentialIssuerIdentifier,
      dpopConstructor: config.requireDpop ? dpopConstructor : nil
    )
    
    authorizeIssuance = AuthorizeIssuance(
      config: config,
      authorizer: authorizer,
      challenger: challenger,
      issuerMetadata: issuerMetadata
    )
    
    try? config.client.ensureSupportedByAuthorizationServer(
      self.authorizationServerMetadata
    )
    
    issuanceRequester = IssuanceRequester(
      issuerMetadata: issuerMetadata,
      poster: Poster(session: session),
      dpopConstructor: dpopConstructor
    )
    
    deferredIssuanceRequester = IssuanceRequester(
      issuerMetadata: issuerMetadata,
      poster: Poster(session: session)
    )
    
    notifyIssuer = NotifyIssuer(
      issuerMetadata: issuerMetadata,
      poster: Poster(session: session)
    )
    
    if let nonceEndpoint = issuerMetadata.nonceEndpoint {
      nonceEndpointClient = NonceEndpointClient(nonceEndpoint: nonceEndpoint)
    } else {
      nonceEndpointClient = nil
    }
  }
  
  public init(
    authorizationServerMetadata: IdentityAndAccessManagementMetadata,
    issuerMetadata: CredentialIssuerMetadata,
    config: OpenId4VCIConfig,
    parPoster: PostingType = Poster(),
    tokenPoster: PostingType = Poster(),
    requesterPoster: PostingType = Poster(),
    deferredRequesterPoster: PostingType = Poster(),
    notificationPoster: PostingType = Poster(),
    challengePoster: PostingType = Poster(),
    noncePoster: PostingType = Poster(),
    dpopConstructor: DPoPConstructorType? = nil
  ) throws {
    self.authorizationServerMetadata = authorizationServerMetadata
    self.issuerMetadata = issuerMetadata
    self.config = config
    
    if let challengeEndpoint = authorizationServerMetadata.challengeEndpointURI {
      challenger = ChallengeEndpointClient(
        poster: challengePoster,
        challengeEndpoint: challengeEndpoint
      )
    } else {
      challenger = nil
    }
    
    authorizer = try AuthorizationServerClient(
      challenger: challenger,
      parPoster: parPoster,
      tokenPoster: tokenPoster,
      config: config,
      authorizationServerMetadata: authorizationServerMetadata,
      credentialIssuerIdentifier: issuerMetadata.credentialIssuerIdentifier,
      dpopConstructor: dpopConstructor
    )
    
    authorizeIssuance = AuthorizeIssuance(
      config: config,
      authorizer: authorizer,
      challenger: challenger,
      issuerMetadata: issuerMetadata
    )
    
    try? config.client.ensureSupportedByAuthorizationServer(
      self.authorizationServerMetadata
    )
    
    issuanceRequester = IssuanceRequester(
      issuerMetadata: issuerMetadata,
      poster: requesterPoster,
      dpopConstructor: dpopConstructor
    )
    
    deferredIssuanceRequester = IssuanceRequester(
      issuerMetadata: issuerMetadata,
      poster: deferredRequesterPoster
    )
    
    notifyIssuer = NotifyIssuer(
      issuerMetadata: issuerMetadata,
      poster: notificationPoster
    )
    
    if let nonceEndpoint = issuerMetadata.nonceEndpoint {
      nonceEndpointClient = NonceEndpointClient(
        poster: noncePoster,
        nonceEndpoint: nonceEndpoint
      )
    } else {
      nonceEndpointClient = nil
    }
  }
  
  public func setDeferredResponseEncryptionSpec(_ deferredResponseEncryptionSpec: IssuanceResponseEncryptionSpec?) async {
    self.deferredResponseEncryptionSpec = deferredResponseEncryptionSpec
  }
  
  public func prepareAuthorizationRequest(
    credentialOffer: CredentialOffer
  ) async throws -> AuthorizationRequested {
    try await authorizeIssuance.prepareAuthorizationRequest(
      credentialOffer: credentialOffer
    )
  }
  
  public func authorizeWithPreAuthorizationCode(
    credentialOffer: CredentialOffer,
    authorizationCode: IssuanceAuthorization,
    client: Client,
    transactionCode: String?,
    authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest = .doNotInclude
  ) async throws -> AuthorizedRequest {
    try await authorizeIssuance.authorizeWithPreAuthorizationCode(
      credentialOffer: credentialOffer,
      authorizationCode: authorizationCode,
      client: client,
      transactionCode: transactionCode,
      authorizationDetailsInTokenRequest: authorizationDetailsInTokenRequest
    )
  }
  
  public func authorizeWithAuthorizationCode(
    serverState: String,
    request: AuthorizationRequested,
    authorizationCode: AuthorizationCode,
    authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest = .doNotInclude,
    grant: Grants
  ) async throws -> AuthorizedRequest {
    
    if serverState != request.state {
      throw ValidationError.stateMismatch(serverState, request.state)
    }
    
    return try await authorizeIssuance.authorizeWithAuthorizationCode(
      grant: grant,
      request: request,
      authorizationCode: authorizationCode,
      authorizationDetailsInTokenRequest: authorizationDetailsInTokenRequest
    )
  }
  
  public func requestCredential(
    request: AuthorizedRequest,
    bindingKeys: [BindingKey],
    requestPayload: IssuanceRequestPayload,
    responseEncryptionSpecProvider: @Sendable (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> SubmittedRequest {
    
    let encryptionSpec = try encryptionSpec()
    
    switch requestPayload {
    case .identifierBased(
      let credentialConfigurationIdentifier,
      let credentialIdentifier
    ):
      return try await identifierBasedRequest(
        authorizedRequest: request,
        token: request.accessToken,
        bindingKeys: bindingKeys,
        credentialIdentifier: credentialIdentifier,
        issuancePayload: requestPayload,
        credentialConfigurationIdentifier: credentialConfigurationIdentifier,
        encryptionSpec: encryptionSpec,
        responseEncryptionSpecProvider: responseEncryptionSpecProvider
      )
      
    case .configurationBased(
      let credentialConfigurationIdentifier
    ):
      return try await formatBasedRequest(
        authorizedRequest: request,
        token: request.accessToken,
        bindingKeys: bindingKeys,
        credentialConfigurationIdentifier: credentialConfigurationIdentifier,
        issuancePayload: requestPayload,
        encryptionSpec: encryptionSpec,
        responseEncryptionSpecProvider: responseEncryptionSpecProvider
      )
    }
  }
}

private extension Issuer {
  
  private func requestIssuance(
    token: IssuanceAccessToken,
    dPopNonce: Nonce?,
    requestEncryptionSpec: EncryptionSpec?,
    issuanceRequestSupplier: () async throws -> CredentialIssuanceRequest
  ) async throws -> SubmittedRequest {
    let credentialRequest = try await issuanceRequestSupplier()
    switch credentialRequest {
    case .single(let single, let encryptionSpec):
      self.deferredResponseEncryptionSpec = encryptionSpec
      let credentialIssuanceResponse = try await issuanceRequester.placeIssuanceRequest(
        accessToken: token,
        request: single,
        dPopNonce: dPopNonce,
        maxRetries: Constants.MAX_RETRIES,
        encryptionSpec: requestEncryptionSpec
      )
        
        return .success(
            response: credentialIssuanceResponse
          )
    }
  }
  
  func handleIssuanceError(
    _ error: Error
  ) -> Result<SubmittedRequest, Error> {
    if let issuanceError = error as? CredentialIssuanceError {
      switch issuanceError {
      case .invalidProof(
        let errorDescription
      ):
        return .success(
          .invalidProof(
            errorDescription: errorDescription
          )
        )
      default: return .failure(
        ValidationError.error(
          reason: error.localizedDescription
        )
      )
      }
    } else {
      return .failure(
        ValidationError.error(
          reason: error.localizedDescription
        )
      )
    }
  }
  
  func formatBasedRequest(
    authorizedRequest: AuthorizedRequest,
    token: IssuanceAccessToken,
    bindingKeys: [BindingKey] = [],
    credentialConfigurationIdentifier: CredentialConfigurationIdentifier,
    issuancePayload: IssuanceRequestPayload,
    encryptionSpec: EncryptionSpec?,
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> SubmittedRequest {
    
    guard let supportedCredential = issuerMetadata
      .credentialsSupported[credentialConfigurationIdentifier] else {
      throw ValidationError.error(reason: "Invalid Supported credential for requestSingle")
    }
    
    let proofs = try await obtainProofs(
      authorizedRequest: authorizedRequest,
      batchCredentialIssuance: issuerMetadata.batchCredentialIssuance,
      bindingKeys: bindingKeys,
      supportedCredential: supportedCredential
    )
    
    return try await requestIssuance(
      token: token,
      dPopNonce: proofs.dPopNonce ?? authorizedRequest.dPopNonce,
      requestEncryptionSpec: encryptionSpec
    ) {
      return try supportedCredential.toIssuanceRequest(
        requester: issuanceRequester,
        proofs: proofs.actualProofs,
        issuancePayload: issuancePayload,
        responseEncryptionSpecProvider: responseEncryptionSpecProvider
      )
    }
  }
  
  func identifierBasedRequest(
    authorizedRequest: AuthorizedRequest,
    token: IssuanceAccessToken,
    bindingKeys: [BindingKey] = [],
    credentialIdentifier: CredentialIdentifier,
    issuancePayload: IssuanceRequestPayload,
    credentialConfigurationIdentifier: CredentialConfigurationIdentifier,
    encryptionSpec: EncryptionSpec?,
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> SubmittedRequest {
    
    guard let supportedCredential = issuerMetadata
      .credentialsSupported[credentialConfigurationIdentifier] else {
      throw ValidationError.error(reason: "Invalid Supported credential for requestSingle")
    }
    
    let proofs = try await obtainProofs(
      authorizedRequest: authorizedRequest,
      batchCredentialIssuance: issuerMetadata.batchCredentialIssuance,
      bindingKeys: bindingKeys,
      supportedCredential: supportedCredential
    )
    
    return try await requestIssuance(
      token: token,
      dPopNonce: proofs.dPopNonce ?? authorizedRequest.dPopNonce,
      requestEncryptionSpec: encryptionSpec
    ) {
      return try supportedCredential.toIssuanceRequest(
        requester: issuanceRequester,
        proofs: proofs.actualProofs,
        issuancePayload: issuancePayload,
        responseEncryptionSpecProvider: responseEncryptionSpecProvider
      )
    }
  }
  
  func obtainProofs(
    authorizedRequest: AuthorizedRequest,
    batchCredentialIssuance: BatchCredentialIssuance?,
    bindingKeys: [BindingKey],
    supportedCredential: CredentialSupported
  ) async throws -> (actualProofs: [Proof], dPopNonce: Nonce?) {
    let proofsRequired = proofsRequirement(credentialSupported: supportedCredential)
    switch proofsRequired {
    case .proofNotRequired:
      return ([], nil)
    default:
      let cNonce = try? await nonceEndpointClient?.getNonce().get()
      
      try await validateBindingKeys(
        credentialSpec: supportedCredential,
        bindingKeys: bindingKeys
      )
      
      let proofs = await calculateProofs(
        bindingKeys: bindingKeys,
        supportedCredential: supportedCredential,
        omitIss: authorizedRequest.grantType == .preAuthorizationCode || authorizedRequest.grantType == .both,
        nonce: cNonce?.nonce.cNonce
      )
      switch proofs.count {
      case .zero:
        return (proofs, cNonce?.dPoPNonce)
      case 1:
        return (proofs, cNonce?.dPoPNonce)
      default:
        if let batchSize = batchCredentialIssuance?.batchSize,
           proofs.count > batchSize {
          throw ValidationError.issuerBatchSizeLimitExceeded(batchSize)
        }
        return (proofs, cNonce?.dPoPNonce)
      }
    }
  }
  
  private func validateBindingKeys(
    credentialSpec: CredentialSupported,
    bindingKeys: [BindingKey]
  ) async throws {
    
    if let first = bindingKeys.first {
      let allSameCase = bindingKeys.allSatisfy { $0 == first }
      guard allSameCase else {
        throw CredentialIssuanceError.combinationOfBindingKeys
      }
    }
    
    let keyAttestationRequirement = credentialSpec.proofTypesSupported?["jwt"]?.keyAttestationRequirement
    switch keyAttestationRequirement {
    case .required, .requiredNoConstraints:
      if bindingKeys.filter({ key in
        switch key {
        case .jwtKeyAttestation, .attestation:
          true
        default: false
        }
      }).isEmpty {
        throw CredentialIssuanceError.proofTypeKeyAttestationRequired
      }
    default: break
    }
  }
  
  private func calculateProofs(
    bindingKeys: [BindingKey],
    supportedCredential: CredentialSupported,
    omitIss: Bool,
    nonce: String?
  ) async -> [Proof] {
    /// Filter for keys we care about
    let eligibleKeys = bindingKeys.filter {
      switch $0 {
      case .jwt, .jwtKeyAttestation, .attestation: true
      default: false
      }
    }
    
    /// Grab the first attestation function, if any
    let attestationFunction = bindingKeys
      .first(where: { $0.isAttestationCapable })?
      .attestationFunction
    
    /// Resolve the attestation JWT once; if we have a function
    let attestationJwt = try? await attestationFunction?(nonce)
    
    /// Build proofs
    let proofs = await eligibleKeys.asyncCompactMap { key in
      try? await key.toSupportedProof(
        issuanceRequester: issuanceRequester,
        credentialSpec: supportedCredential,
        keyAttestationJwt: attestationJwt,
        cNonce: nonce,
        omitIss: omitIss
      )
    }
    return proofs
  }
  
  private func proofsRequirement(
    credentialSupported: CredentialSupported
  ) -> CredentialProofsRequirement {
    if credentialSupported.supportsProofTypes() == false {
      return .proofNotRequired
    } else if nonceEndpointClient == nil {
      return .proofRequiredWithoutCNonce
    }
    return .proofRequiredWithCNonce
  }
}

public extension Issuer {
  
  static func createDeferredIssuer(
    deferredCredentialEndpoint: CredentialIssuerEndpoint?,
    deferredRequesterPoster: PostingType,
    config: OpenId4VCIConfig
  ) throws -> Issuer {
    try Issuer(
      authorizationServerMetadata: .oauth(
        .init(
          authorizationEndpoint: Constants.url,
          tokenEndpoint: Constants.url,
          pushedAuthorizationRequestEndpoint: Constants.url
        )
      ),
      issuerMetadata: .init(
        deferredCredentialEndpoint: deferredCredentialEndpoint
      ),
      config: config,
      deferredRequesterPoster: deferredRequesterPoster
    )
  }
  
  static func createResponseEncryptionSpec(
    _ issuerResponseEncryptionMetadata: CredentialResponseEncryption,
    privateKeyData: Data? = nil
  ) -> IssuanceResponseEncryptionSpec? {
    switch issuerResponseEncryptionMetadata {
    case .notSupported:
      return Self.createResponseEncryptionSpecFrom(
        algorithmsSupported: [.init(.ECDH_ES)],
        encryptionMethodsSupported: [.init(.A128GCM)],
        privateKeyData: privateKeyData
      )
    case let .required(
      algorithmsSupported,
      encryptionMethodsSupported,
      compressionMethodsSupported
    ):
      return Self.createResponseEncryptionSpecFrom(
        algorithmsSupported: algorithmsSupported,
        encryptionMethodsSupported: encryptionMethodsSupported,
        compressionMethodsSupported: compressionMethodsSupported,
        privateKeyData: privateKeyData
      )
    case let .notRequired(
      algorithmsSupported,
      encryptionMethodsSupported,
      compressionMethodsSupported
    ):
      return Self.createResponseEncryptionSpecFrom(
        algorithmsSupported: algorithmsSupported,
        encryptionMethodsSupported: encryptionMethodsSupported,
        compressionMethodsSupported: compressionMethodsSupported,
        privateKeyData: privateKeyData
      )
    }
  }
  
  static func createResponseEncryptionSpecFrom(
    algorithmsSupported: [JWEAlgorithm],
    encryptionMethodsSupported: [JOSEEncryptionMethod],
    compressionMethodsSupported: [CompressionAlgorithm]? = nil,
    privateKeyData: Data? = nil
  ) -> IssuanceResponseEncryptionSpec? {
    let firstAsymmetricAlgorithm = algorithmsSupported.first {
      JWEAlgorithm.Family.parse(.ASYMMETRIC).contains($0)
    }
    
    guard
      let algorithm = firstAsymmetricAlgorithm
    else {
      return nil
    }
    
    let privateKey: SecKey?
    var jwk: JWK?
    if JWEAlgorithm.Family.parse(.RSA).contains(algorithm) {
      privateKey = if let privateKeyData {
        try? KeyController.generateRSAPrivateKey(with: privateKeyData)
      } else {
        try? KeyController.generateRSAPrivateKey()
      }
      if let privateKey,
         let publicKey = try? KeyController.generateRSAPublicKey(from: privateKey) {
        jwk = try? RSAPublicKey(
          publicKey: publicKey,
          additionalParameters: [
            "use": "enc",
            "kid": UUID().uuidString,
            "alg": algorithm.name
          ]
        )
      }
    } else if JWEAlgorithm.Family.parse(.ECDH_ES).contains(algorithm) {
      privateKey = if let privateKeyData {
        try? KeyController.generateECPrivateKey(with: privateKeyData)
      } else {
        try? KeyController.generateECDHPrivateKey()
      }
      if let privateKey,
         let publicKey = try? KeyController.generateECDHPublicKey(from: privateKey) {
        jwk = try? ECPublicKey(
          publicKey: publicKey,
          additionalParameters: [
            "use": "enc",
            "kid": UUID().uuidString,
            "alg": algorithm.name
          ]
        )
      }
    } else {
      privateKey = nil
    }
    
    guard
      let key = privateKey,
      let encryptionMethodsSupported = encryptionMethodsSupported.first
    else {
      return nil
    }
    
    return IssuanceResponseEncryptionSpec(
      jwk: jwk,
      privateKey: key,
      algorithm: algorithm,
      encryptionMethod: encryptionMethodsSupported
    )
  }
  
  func requestDeferredCredential(
    request: AuthorizedRequest,
    transactionId: TransactionId,
    dPopNonce: Nonce?
  ) async throws -> DeferredCredentialIssuanceResponse {
    
    return try await deferredIssuanceRequester.placeDeferredCredentialRequest(
      accessToken: request.accessToken,
      transactionId: transactionId,
      dPopNonce: dPopNonce,
      maxRetries: Constants.MAX_RETRIES,
      issuanceResponseEncryptionSpec: deferredResponseEncryptionSpec
    )
  }
  
  func notify(
    authorizedRequest: AuthorizedRequest,
    notificationId: NotificationObject,
    dPopNonce: Nonce?
  ) async throws {
    try await notifyIssuer.notify(
      authorizedRequest: authorizedRequest,
      notification: notificationId,
      dPopNonce: dPopNonce
    )
  }
  
  func refresh(
    clientId: String,
    authorizedRequest: AuthorizedRequest,
    dPopNonce: Nonce? = nil
  ) async throws -> AuthorizedRequest {
    if let refreshToken = authorizedRequest.refreshToken {
        let (accessToken, refreshToken, _, _, timeStamp, _) = try await authorizer.refreshAccessToken(
          clientId: clientId,
          refreshToken: refreshToken,
          dpopNonce: dPopNonce,
          maxRetries: Constants.MAX_RETRIES
        )
        return authorizedRequest.replacing(
            accessToken: accessToken,
            timeStamp: timeStamp?.asTimeInterval ?? .zero
          )
    }
    
    return authorizedRequest
  }
  
  func refresh(
    client: Client,
    authorizedRequest: AuthorizedRequest,
    dPopNonce: Nonce?
  ) async throws -> AuthorizedRequest {
    if let refreshToken = authorizedRequest.refreshToken {
        let (accessToken, refreshToken, _, _, timeStamp, _) = try await authorizer.refreshAccessToken(
          client: client,
          refreshToken: refreshToken,
          dpopNonce: dPopNonce,
          maxRetries: Constants.MAX_RETRIES
        )
          return authorizedRequest.replacing(
            accessToken: accessToken,
			refreshToken: refreshToken,
            timeStamp: timeStamp?.asTimeInterval ?? .zero
          )
    }
    return authorizedRequest
  }
}

internal extension Client {
  
  private static let ATTEST_JWT_CLIENT_AUTH = "attest_jwt_client_auth"
  
  func ensureSupportedByAuthorizationServer(_ authorizationServerMetadata: IdentityAndAccessManagementMetadata) throws {
    
    let tokenEndpointAuthMethods = authorizationServerMetadata.tokenEndpointAuthMethods
    
    switch self {
    case .attested:
      let expectedMethod = Self.ATTEST_JWT_CLIENT_AUTH
      guard tokenEndpointAuthMethods.contains(expectedMethod) else {
        throw ValidationError.error(reason: ("\(Self.ATTEST_JWT_CLIENT_AUTH) not supported by authorization server"))
      }
      
    default:
      break
    }
  }
}
