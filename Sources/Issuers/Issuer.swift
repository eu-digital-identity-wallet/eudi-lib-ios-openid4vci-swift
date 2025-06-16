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
public protocol IssuerType {
  
  /// Initiates an authorization request using a credential offer.
  ///
  /// - Parameter credentialOffer: The credential offer containing necessary details for authorization.
  /// - Returns: A result containing either an `UnauthorizedRequest` if the request is successful or an `Error` otherwise.
  func prepareAuthorizationRequest(
    credentialOffer: CredentialOffer
  ) async throws -> Result<AuthorizationRequestPrepared, Error>
  
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
  ) async -> Result<AuthorizedRequest, Error>
  
  /// Handles the authorization code and updates the request status.
  ///
  /// - Parameters:
  ///   - parRequested: The unauthorized request that needs authorization.
  ///   - authorizationCode: The authorization code issued by the issuer.
  /// - Returns: A result containing either an updated `UnauthorizedRequest` or an `Error`.
  func handleAuthorizationCode(
    request: AuthorizationRequestPrepared,
    authorizationCode: IssuanceAuthorization
  ) async -> Result<AuthorizationRequestPrepared, Error>
  
  /// Handles the provided authorization code and updates the authorization request state.
  ///
  /// - Parameters:
  ///   - request: The `AuthorizationRequestPrepared` object representing the state of the authorization request.
  ///   - code: The authorization code received from the authorization server. This parameter is passed as `inout`
  ///           in case it needs to be modified or consumed during processing.
  /// - Returns: A `Result` containing the potentially updated `AuthorizationRequestPrepared` on success,
  ///            or an `Error` if the code is invalid or the processing fails.
  func handleAuthorizationCode(
    request: AuthorizationRequestPrepared,
    code: inout String
  ) async -> Result<AuthorizationRequestPrepared, Error>
  
  /// Completes the authorization process using an authorization code.
  ///
  /// - Parameters:
  ///   - authorizationCode: The unauthorized request containing the authorization code.
  ///   - authorizationDetailsInTokenRequest: Additional authorization details for the token request.
  /// - Returns: A result containing either an `AuthorizedRequest` if successful or an `Error` otherwise.
  func authorizeWithAuthorizationCode(
    request: AuthorizationRequestPrepared,
    authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest
  ) async -> Result<AuthorizedRequest, Error>
  
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
  ) async throws -> Result<SubmittedRequest, Error>
  
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
  ) async throws -> Result<DeferredCredentialIssuanceResponse, Error>
  
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
  ) async throws -> Result<Void, Error>
  
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
  ) async -> Result<AuthorizedRequest, Error>
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
    
    authorizer = try AuthorizationServerClient(
      parPoster: Poster(session: session),
      tokenPoster: Poster(session: session),
      config: config,
      authorizationServerMetadata: authorizationServerMetadata,
      credentialIssuerIdentifier: issuerMetadata.credentialIssuerIdentifier,
      dpopConstructor: dpopConstructor
    )
    
    authorizeIssuance = AuthorizeIssuance(
      config: config,
      authorizer: authorizer,
      issuerMetadata: issuerMetadata
    )
    
    try config.client.ensureSupportedByAuthorizationServer(
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
    noncePoster: PostingType = Poster(),
    dpopConstructor: DPoPConstructorType? = nil
  ) throws {
    self.authorizationServerMetadata = authorizationServerMetadata
    self.issuerMetadata = issuerMetadata
    self.config = config
    
    authorizer = try AuthorizationServerClient(
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
      issuerMetadata: issuerMetadata
    )
    
    try config.client.ensureSupportedByAuthorizationServer(
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
      nonceEndpointClient = NonceEndpointClient(nonceEndpoint: nonceEndpoint)
    } else {
      nonceEndpointClient = nil
    }
  }
  
  public func setDeferredResponseEncryptionSpec(_ deferredResponseEncryptionSpec: IssuanceResponseEncryptionSpec?) {
    self.deferredResponseEncryptionSpec = deferredResponseEncryptionSpec
  }
  
  public func prepareAuthorizationRequest(
    credentialOffer: CredentialOffer
  ) async throws -> Result<AuthorizationRequestPrepared, Error> {
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
  ) async -> Result<AuthorizedRequest, Error> {
    await authorizeIssuance.authorizeWithPreAuthorizationCode(
      credentialOffer: credentialOffer,
      authorizationCode: authorizationCode,
      client: client,
      transactionCode: transactionCode,
      authorizationDetailsInTokenRequest: authorizationDetailsInTokenRequest
    )
  }
  
  public func authorizeWithAuthorizationCode(
    request: AuthorizationRequestPrepared,
    authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest = .doNotInclude
  ) async -> Result<AuthorizedRequest, Error> {
    await authorizeIssuance.authorizeWithAuthorizationCode(
      request: request,
      authorizationDetailsInTokenRequest: authorizationDetailsInTokenRequest
    )
  }
  
  public func handleAuthorizationCode(
    request: AuthorizationRequestPrepared,
    code: inout String
  ) async -> Result<AuthorizationRequestPrepared, Error> {
    switch request {
    case .prepared(let request):
      do {
        return .success(
          .authorizationCode(
            try .init(
              credentials: request.credentials,
              authorizationCode: try .init(authorizationCode: code),
              pkceVerifier: request.pkceVerifier,
              configurationIds: request.configurationIds,
              dpopNonce: request.dpopNonce
            )
          )
        )
      } catch {
        return .failure(
          ValidationError.error(reason: error.localizedDescription)
        )
      }
    case .authorizationCode:
      return .failure(
        ValidationError.error(
          reason: ".prepared is required"
        )
      )
    }
  }
  
  public func handleAuthorizationCode(
    request: AuthorizationRequestPrepared,
    authorizationCode: IssuanceAuthorization
  ) async -> Result<AuthorizationRequestPrepared, Error> {
    switch request {
    case .prepared(let request):
      switch authorizationCode {
      case .authorizationCode(let authorizationCode):
        do {
          return .success(
            .authorizationCode(
              try .init(
                credentials: request.credentials,
                authorizationCode: try IssuanceAuthorization(authorizationCode: authorizationCode),
                pkceVerifier: request.pkceVerifier,
                configurationIds: request.configurationIds,
                dpopNonce: request.dpopNonce
              )
            )
          )
        } catch {
          return .failure(
            ValidationError.error(
              reason: error.localizedDescription
            )
          )
        }
      default:
        return .failure(
          ValidationError.error(
            reason: ".prepared & .authorizationCode is required"
          )
        )
      }
    case .authorizationCode:
      return .failure(
        ValidationError.error(
          reason: ".prepared is required"
        )
      )
    }
  }
  
  public func requestCredential(
    request: AuthorizedRequest,
    bindingKeys: [BindingKey],
    requestPayload: IssuanceRequestPayload,
    responseEncryptionSpecProvider: @Sendable (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> Result<SubmittedRequest, Error> {
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
        responseEncryptionSpecProvider: responseEncryptionSpecProvider
      )
    }
  }
}

private extension Issuer {
  
  private func requestIssuance(
    token: IssuanceAccessToken,
    dPopNonce: Nonce?,
    issuanceRequestSupplier: () async throws -> CredentialIssuanceRequest
  ) async throws -> Result<SubmittedRequest, Error> {
    let credentialRequest = try await issuanceRequestSupplier()
    switch credentialRequest {
    case .single(let single, let encryptionSpec):
      self.deferredResponseEncryptionSpec = encryptionSpec
      let result = try await issuanceRequester.placeIssuanceRequest(
        accessToken: token,
        request: single,
        dPopNonce: dPopNonce,
        retry: true
      )
      switch result {
      case .success(let response):
        return .success(
          .success(
            response: response
          )
        )
      case .failure(let error):
        return handleIssuanceError(error)
      }
    }
  }
  
  func handleIssuanceError(_ error: Error) -> Result<SubmittedRequest, Error> {
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
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> Result<SubmittedRequest, Error> {
    
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
      dPopNonce: authorizedRequest.dPopNonce
    ) {
      return try supportedCredential.toIssuanceRequest(
        requester: issuanceRequester,
        proofs: proofs,
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
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> Result<SubmittedRequest, Error> {
    
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
      dPopNonce: authorizedRequest.dPopNonce
    ) {
      return try supportedCredential.toIssuanceRequest(
        requester: issuanceRequester,
        proofs: proofs,
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
  ) async throws -> [Proof] {
    let proofsRequired = proofsRequirement(credentialSupported: supportedCredential)
    switch proofsRequired {
    case .proofNotRequired:
      return []
    default:
      let cNonce = try? await nonceEndpointClient?.getNonce().get()
      let proofs = await calculateProofs(
        bindingKeys: bindingKeys,
        supportedCredential: supportedCredential,
        nonce: cNonce?.cNonce
      )
      switch proofs.count {
      case .zero:
        return proofs
      case 1:
        return proofs
      default:
        if let batchSize = batchCredentialIssuance?.batchSize,
           proofs.count > batchSize {
          throw ValidationError.issuerBatchSizeLimitExceeded(batchSize)
        }
        return proofs
      }
    }
  }
  
  private func calculateProofs(
    bindingKeys: [BindingKey],
    supportedCredential: CredentialSupported,
    nonce: String?
  ) async -> [Proof] {
    await Task.detached { () -> [Proof] in
      return await (try? bindingKeys.asyncCompactMap { try await $0.toSupportedProof(
        issuanceRequester: self.issuanceRequester,
        credentialSpec: supportedCredential,
        cNonce: nonce
      )}) ?? []
    }.value
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
    case .notRequired:
      return Self.createResponseEncryptionSpecFrom(
        algorithmsSupported: [.init(.RSA_OAEP_256)],
        encryptionMethodsSupported: [.init(.A128CBC_HS256)],
        privateKeyData: privateKeyData
      )
      
    case let .required(algorithmsSupported, encryptionMethodsSupported):
      return Self.createResponseEncryptionSpecFrom(
        algorithmsSupported: algorithmsSupported,
        encryptionMethodsSupported: encryptionMethodsSupported,
        privateKeyData: privateKeyData
      )
    }
  }
  
  static func createResponseEncryptionSpecFrom(
    algorithmsSupported: [JWEAlgorithm],
    encryptionMethodsSupported: [JOSEEncryptionMethod],
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
  ) async throws -> Result<DeferredCredentialIssuanceResponse, Error> {
    
    return try await deferredIssuanceRequester.placeDeferredCredentialRequest(
      accessToken: request.accessToken,
      transactionId: transactionId,
      dPopNonce: dPopNonce,
      retry: true,
      issuanceResponseEncryptionSpec: deferredResponseEncryptionSpec
    )
  }
  
  func notify(
    authorizedRequest: AuthorizedRequest,
    notificationId: NotificationObject,
    dPopNonce: Nonce?
  ) async throws -> Result<Void, Error> {
    
    return try await notifyIssuer.notify(
      authorizedRequest: authorizedRequest,
      notification: notificationId,
      dPopNonce: dPopNonce
    )
  }
  
  func refresh(
    clientId: String,
    authorizedRequest: AuthorizedRequest,
    dPopNonce: Nonce? = nil
  ) async -> Result<AuthorizedRequest, Error> {
    
    if  let refreshToken = authorizedRequest.refreshToken {
      do {
        let token = try await authorizer.refreshAccessToken(
          clientId: clientId,
          refreshToken: refreshToken,
          dpopNonce: dPopNonce,
          retry: true
        )
        switch token {
        case .success(
          (let accessToken, _, _, let timeStamp, _)
        ):
          return .success(authorizedRequest.replacing(
            accessToken: accessToken,
            timeStamp: timeStamp?.asTimeInterval ?? .zero
          )
          )
        case .failure(let error):
          return .failure(error)
        }
      } catch {
        return .failure(error)
      }
    }
    return .success(authorizedRequest)
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
