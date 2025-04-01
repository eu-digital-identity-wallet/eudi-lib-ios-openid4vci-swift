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
  func pushAuthorizationCodeRequest(
    credentialOffer: CredentialOffer
  ) async throws -> Result<UnauthorizedRequest, Error>
  
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
    parRequested: UnauthorizedRequest,
    authorizationCode: IssuanceAuthorization
  ) async -> Result<UnauthorizedRequest, Error>
  
  /// Completes the authorization process using an authorization code.
  ///
  /// - Parameters:
  ///   - authorizationCode: The unauthorized request containing the authorization code.
  ///   - authorizationDetailsInTokenRequest: Additional authorization details for the token request.
  /// - Returns: A result containing either an `AuthorizedRequest` if successful or an `Error` otherwise.
  func authorizeWithAuthorizationCode(
    authorizationCode: UnauthorizedRequest,
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
  
  public var deferredResponseEncryptionSpec: IssuanceResponseEncryptionSpec? = nil
  
  public let authorizationServerMetadata: IdentityAndAccessManagementMetadata
  public let issuerMetadata: CredentialIssuerMetadata
  public let config: OpenId4VCIConfig
  
  private let authorizer: AuthorizationServerClientType
  private let nonceEndpointClient: NonceEndpointClientType?
  private let issuanceRequester: IssuanceRequesterType
  private let deferredIssuanceRequester: IssuanceRequesterType
  private let notifyIssuer: NotifyIssuerType
  
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
  
  public func pushAuthorizationCodeRequest(
    credentialOffer: CredentialOffer
  ) async throws -> Result<UnauthorizedRequest, Error> {
    let credentials = credentialOffer.credentialConfigurationIdentifiers
    let issuerState: String? = switch credentialOffer.grants {
    case .authorizationCode(let code),
        .both(let code, _):
      code.issuerState
    default:
      nil
    }
    
    let (scopes, credentialConfogurationIdentifiers) = try scopesAndCredentialConfigurationIds(credentialOffer: credentialOffer)
    
    let authorizationServerSupportsPar = credentialOffer.authorizationServerMetadata.authorizationServerSupportsPar && config.usePAR
    
    let state = StateValue().value
    
    if authorizationServerSupportsPar {
      do {
        let resource: String? = issuerMetadata.authorizationServers.map { _ in
          credentialOffer.credentialIssuerIdentifier.url.absoluteString
        }
        
        let result: (
          verifier: PKCEVerifier,
          code: GetAuthorizationCodeURL,
          dPopNonce: Nonce?
        ) = try await authorizer.submitPushedAuthorizationRequest(
          scopes: scopes,
          credentialConfigurationIdentifiers: credentialConfogurationIdentifiers,
          state: state,
          issuerState: issuerState,
          resource: resource,
          dpopNonce: nil,
          retry: true
        ).get()
        
        return .success(
          .par(
            .init(
              credentials: try credentials.map { try CredentialIdentifier(value: $0.value) },
              getAuthorizationCodeURL: result.code,
              pkceVerifier: result.verifier,
              state: state,
              configurationIds: credentialConfogurationIdentifiers,
              dpopNonce: result.dPopNonce
            )
          )
        )
      } catch {
        return .failure(ValidationError.error(reason: error.localizedDescription))
      }
    } else {
      do {
        let result: (
          verifier: PKCEVerifier,
          code: GetAuthorizationCodeURL
        ) = try await authorizer.authorizationRequestUrl(
          scopes: scopes,
          credentialConfigurationIdentifiers: credentialConfogurationIdentifiers,
          state: state,
          issuerState: issuerState
        ).get()
        
        return .success(
          .par(
            .init(
              credentials: try credentials.map { try CredentialIdentifier(value: $0.value) },
              getAuthorizationCodeURL: result.code,
              pkceVerifier: result.verifier,
              state: state,
              configurationIds: credentialConfogurationIdentifiers
            )
          )
        )
      } catch {
        return .failure(ValidationError.error(reason: error.localizedDescription))
      }
      
    }
  }
  
  public func authorizeWithPreAuthorizationCode(
    credentialOffer: CredentialOffer,
    authorizationCode: IssuanceAuthorization,
    client: Client,
    transactionCode: String?,
    authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest = .doNotInclude
  ) async -> Result<AuthorizedRequest, Error> {
    
    switch authorizationCode {
    case .preAuthorizationCode(let authorisation, let txCode):
      do {
        if let transactionCode, let txCode {
          if txCode.length != transactionCode.count {
            throw ValidationError.error(reason: "Expected transaction code length is \(txCode.length ?? 0) but code of length \(transactionCode.count) passed")
          }
          
          if txCode.inputMode != .numeric {
            throw ValidationError.error(reason: "Issuers expects transaction code to be numeric but is not.")
          }
        }
        
        let credConfigIdsAsAuthDetails: [CredentialConfigurationIdentifier] = switch authorizationDetailsInTokenRequest {
        case .doNotInclude: []
        case .include(let filter): credentialOffer.credentialConfigurationIdentifiers.filter(filter)
        }
        
        let response = try await authorizer.requestAccessTokenPreAuthFlow(
          preAuthorizedCode: authorisation,
          txCode: txCode,
          client: client,
          transactionCode: transactionCode,
          identifiers: credConfigIdsAsAuthDetails,
          dpopNonce: nil,
          retry: true
        )
        
        switch response {
        case .success(
          (let accessToken, let refreshToken, let identifiers, let expiresIn, let dPopNonce)
        ):
          return .success(
            .init(
              accessToken: try .init(
                accessToken: accessToken.accessToken,
                tokenType: accessToken.tokenType,
                expiresIn: expiresIn?.asTimeInterval ?? .zero
              ),
              refreshToken: try .init(
                refreshToken: refreshToken.refreshToken
              ),
              credentialIdentifiers: identifiers,
              timeStamp: Date().timeIntervalSinceReferenceDate,
              dPopNonce: dPopNonce
            )
          )
        case .failure(let error):
          return .failure(ValidationError.error(reason: error.localizedDescription))
        }
      } catch {
        return .failure(ValidationError.error(reason: error.localizedDescription))
      }
    default:
      return .failure(ValidationError.error(
        reason: "Invalid issuance authorisation, pre authorisation supported only"
      ))
    }
  }
  
  public func authorizeWithAuthorizationCode(
    authorizationCode: UnauthorizedRequest,
    authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest = .doNotInclude
  ) async -> Result<AuthorizedRequest, Error> {
    switch authorizationCode {
    case .par:
      return .failure(
        ValidationError.error(reason: ".authorizationCode case is required")
      )
      
    case .authorizationCode(let request):
      switch request.authorizationCode {
      case .authorizationCode(let authorizationCode):
        do {
          let credConfigIdsAsAuthDetails: [CredentialConfigurationIdentifier] = switch authorizationDetailsInTokenRequest {
          case .doNotInclude: []
          case .include(let filter): request.configurationIds.filter(filter)
          }
          
          let response: (
            accessToken: IssuanceAccessToken,
            refreshToken: IssuanceRefreshToken,
            identifiers: AuthorizationDetailsIdentifiers?,
            tokenType: TokenType?,
            expiresIn: Int?,
            dPopNonce: Nonce?
          ) = try await authorizer.requestAccessTokenAuthFlow(
            authorizationCode: authorizationCode,
            codeVerifier: request.pkceVerifier.codeVerifier,
            identifiers: credConfigIdsAsAuthDetails,
            dpopNonce: request.dpopNonce,
            retry: true
          ).get()
          
          return .success(
            .init(
              accessToken: try .init(
                accessToken: response.accessToken.accessToken,
                tokenType: response.tokenType,
                expiresIn: TimeInterval(response.expiresIn ?? .zero)
              ),
              refreshToken: try .init(
                refreshToken: response.refreshToken.refreshToken
              ),
              credentialIdentifiers: response.identifiers,
              timeStamp: Date().timeIntervalSinceReferenceDate,
              dPopNonce: response.dPopNonce
            )
          )
        } catch {
          return .failure(ValidationError.error(reason: error.localizedDescription))
        }
      default: return .failure(
        ValidationError.error(reason: ".authorizationCode case is required"))
      }
    }
  }
  
  public func handleAuthorizationCode(
    parRequested: UnauthorizedRequest,
    code: inout String
  ) -> Result<UnauthorizedRequest, Error> {
    switch parRequested {
    case .par(let request):
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
    case .authorizationCode(_):
      return .failure(ValidationError.error(reason: ".par is required"))
    }
  }
  
  public func handleAuthorizationCode(
    parRequested: UnauthorizedRequest,
    authorizationCode: IssuanceAuthorization
  ) -> Result<UnauthorizedRequest, Error> {
    switch parRequested {
    case .par(let request):
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
          return .failure(ValidationError.error(reason: error.localizedDescription))
        }
      default: return .failure(ValidationError.error(reason: ".par & .authorizationCode is required"))
      }
    case .authorizationCode(_):
      return .failure(ValidationError.error(reason: ".par is required"))
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
  
  func scopesAndCredentialConfigurationIds(credentialOffer: CredentialOffer) throws -> ([Scope], [CredentialConfigurationIdentifier]) {
    var scopes = [Scope]()
    var configurationIdentifiers = [CredentialConfigurationIdentifier]()
    
    func credentialConfigurationById(id: CredentialConfigurationIdentifier) throws -> CredentialSupported {
      let issuerMetadata = credentialOffer.credentialIssuerMetadata
      return try unwrapOrThrow(issuerMetadata.credentialsSupported[id], error: ValidationError.error(reason: "\(id) was not found within issuer metadata"))
    }
    
    for id in credentialOffer.credentialConfigurationIdentifiers {
      let credentialConfiguration = try credentialConfigurationById(id: id)
      switch config.authorizeIssuanceConfig {
      case .favorScopes:
        if let scope = credentialConfiguration.getScope() {
          scopes.append(try Scope(scope))
        } else {
          configurationIdentifiers.append(id)
        }
      case .authorizationDetails:
        configurationIdentifiers.append(id)
      }
    }
    return (scopes, configurationIdentifiers)
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
  
  static func createResponseEncryptionSpec(_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec? {
    switch issuerResponseEncryptionMetadata {
    case .notRequired:
      return Self.createResponseEncryptionSpecFrom(
        algorithmsSupported: [.init(.RSA_OAEP_256)],
        encryptionMethodsSupported: [.init(.A128CBC_HS256)]
      )
      
    case let .required(algorithmsSupported, encryptionMethodsSupported):
      return Self.createResponseEncryptionSpecFrom(
        algorithmsSupported: algorithmsSupported,
        encryptionMethodsSupported: encryptionMethodsSupported
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
    var jwk: JWK? = nil
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
        throw ValidationError.error(reason:("\(Self.ATTEST_JWT_CLIENT_AUTH) not supported by authorization server"))
      }
    default:
      break
    }
  }
}
