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

public protocol IssuerType {
  
  func pushAuthorizationCodeRequest(
    credentialOffer: CredentialOffer
  ) async throws -> Result<UnauthorizedRequest, Error>
  
  func authorizeWithPreAuthorizationCode(
    credentialOffer: CredentialOffer,
    authorizationCode: IssuanceAuthorization,
    clientId: String,
    transactionCode: String?,
    authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest
  ) async -> Result<AuthorizedRequest, Error>
  
  func handleAuthorizationCode(
    parRequested: UnauthorizedRequest,
    authorizationCode: IssuanceAuthorization
  ) async -> Result<UnauthorizedRequest, Error>
  
  func authorizeWithAuthorizationCode(
    authorizationCode: UnauthorizedRequest,
    authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest
  ) async -> Result<AuthorizedRequest, Error>
  
  func request(
    noProofRequest: AuthorizedRequest,
    requestPayload: IssuanceRequestPayload,
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> Result<SubmittedRequest, Error>
  
  func request(
    proofRequest: AuthorizedRequest,
    bindingKeys: [BindingKey],
    requestPayload: IssuanceRequestPayload,
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> Result<SubmittedRequest, Error>
  
  func requestDeferredIssuance(
    proofRequest: AuthorizedRequest,
    transactionId: TransactionId,
    dPopNonce: Nonce?
  ) async throws -> Result<DeferredCredentialIssuanceResponse, Error>
  
  func notify(
    authorizedRequest: AuthorizedRequest,
    notificationId: NotificationObject,
    dPopNonce: Nonce?
  ) async throws -> Result<Void, Error>
}

public actor Issuer: IssuerType {
  
  public var deferredResponseEncryptionSpec: IssuanceResponseEncryptionSpec? = nil
  
  public let authorizationServerMetadata: IdentityAndAccessManagementMetadata
  public let issuerMetadata: CredentialIssuerMetadata
  public let config: OpenId4VCIConfig
  
  private let authorizer: AuthorizationServerClientType
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
    clientId: String,
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
          clientId: clientId,
          transactionCode: transactionCode,
          identifiers: credConfigIdsAsAuthDetails,
          dpopNonce: nil,
          retry: true
        )
        
        switch response {
        case .success(
          (let accessToken, let nonce, let identifiers, let expiresIn, let dPopNonce)
        ):
          if let cNonce = nonce {
            return .success(
              .proofRequired(
                accessToken: try IssuanceAccessToken(
                  accessToken: accessToken.accessToken,
                  tokenType: accessToken.tokenType, 
                  expiresIn: TimeInterval(expiresIn ?? .zero)
                ),
                refreshToken: nil,
                cNonce: cNonce,
                credentialIdentifiers: identifiers, 
                timeStamp: Date().timeIntervalSinceReferenceDate,
                dPopNonce: dPopNonce
              )
            )
          } else {
            return .success(
              .noProofRequired(
                accessToken: try IssuanceAccessToken(
                  accessToken: accessToken.accessToken,
                  tokenType: accessToken.tokenType,
                  expiresIn: TimeInterval(expiresIn ?? .zero)
                ),
                refreshToken: nil,
                credentialIdentifiers: identifiers,
                timeStamp: Date().timeIntervalSinceReferenceDate,
                dPopNonce: dPopNonce
              )
            )
          }
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
            nonce: CNonce?,
            identifiers: AuthorizationDetailsIdentifiers?,
            tokenType: TokenType?,
            expiresIn: Int?,
            dPopNonce: Nonce?
          ) = try await authorizer.requestAccessTokenAuthFlow(
            authorizationCode: authorizationCode,
            codeVerifier: request.pkceVerifier.codeVerifier,
            identifiers: credConfigIdsAsAuthDetails,
            dpopNonce: nil,
            retry: true
          ).get()
          
          if let cNonce = response.nonce {
            return .success(
              .proofRequired(
                accessToken: try IssuanceAccessToken(
                  accessToken: response.accessToken.accessToken,
                  tokenType: response.tokenType,
                  expiresIn: TimeInterval(response.expiresIn ?? .zero)
                ),
                refreshToken: nil,
                cNonce: cNonce,
                credentialIdentifiers: response.identifiers,
                timeStamp: Date().timeIntervalSinceReferenceDate,
                dPopNonce: response.dPopNonce
              )
            )
          } else {
            return .success(
              .noProofRequired(
                accessToken: try IssuanceAccessToken(
                  accessToken: response.accessToken.accessToken,
                  tokenType: response.tokenType,
                  expiresIn: TimeInterval(response.expiresIn ?? .zero)
                ),
                refreshToken: nil,
                credentialIdentifiers: response.identifiers,
                timeStamp: Date().timeIntervalSinceReferenceDate,
                dPopNonce: response.dPopNonce
              )
            )
          }
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
              authorizationCode: try IssuanceAuthorization(authorizationCode: code),
              pkceVerifier: request.pkceVerifier,
              configurationIds: request.configurationIds
            )
          )
        )
      } catch {
        return .failure(ValidationError.error(reason: error.localizedDescription))
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
                configurationIds: request.configurationIds
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
  
  private func accessToken(from request: AuthorizedRequest) -> IssuanceAccessToken {
    switch request {
    case .noProofRequired(let token, _, _, _, _):
      return token
    case .proofRequired(let token, _, _, _, _, _):
      return token
    }
  }
  
  private func cNonce(from request: AuthorizedRequest) -> CNonce? {
    switch request {
    case .noProofRequired:
      return nil
    case .proofRequired(_, _, let cnonce, _, _, _):
      return cnonce
    }
  }
  
  public func request(
    noProofRequest: AuthorizedRequest,
    requestPayload: IssuanceRequestPayload,
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> Result<SubmittedRequest, Error> {
    
    guard let token = noProofRequest.noProofToken else {
      throw ValidationError.error(reason: "Invalid Supported credential for requestSingle")
    }
    
    switch requestPayload {
    case .identifierBased(
      let credentialConfigurationIdentifier,
      let credentialIdentifier
    ):
      return try await identifierBasedRequest(
        authorizedRequest: noProofRequest,
        token: token,
        credentialIdentifier: credentialIdentifier,
        credentialConfigurationIdentifier: credentialConfigurationIdentifier,
        responseEncryptionSpecProvider: responseEncryptionSpecProvider
      )
      
    case .configurationBased(
      let credentialConfigurationIdentifier,
      let claimSet
    ):
      return try await formatBasedRequest(
        authorizedRequest: noProofRequest,
        token: token,
        claimSet: claimSet,
        credentialConfigurationIdentifier: credentialConfigurationIdentifier,
        responseEncryptionSpecProvider: responseEncryptionSpecProvider
      )
    }
  }
  
  public func request(
    proofRequest: AuthorizedRequest,
    bindingKeys: [BindingKey],
    requestPayload: IssuanceRequestPayload,
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> Result<SubmittedRequest, Error> {
    guard let token = proofRequest.proofToken else {
      throw ValidationError.error(reason: "Invalid Supported credential for requestSingle")
    }
    
    switch requestPayload {
    case .identifierBased(
      let credentialConfigurationIdentifier,
      let credentialIdentifier
    ):
      return try await identifierBasedRequest(
        authorizedRequest: proofRequest,
        token: token,
        bindingKeys: bindingKeys,
        credentialIdentifier: credentialIdentifier,
        credentialConfigurationIdentifier: credentialConfigurationIdentifier,
        responseEncryptionSpecProvider: responseEncryptionSpecProvider
      )
      
    case .configurationBased(
      let credentialConfigurationIdentifier,
      let claimSet
    ):
      return try await formatBasedRequest(
        authorizedRequest: proofRequest,
        token: token,
        claimSet: claimSet,
        bindingKeys: bindingKeys,
        cNonce: cNonce(from: proofRequest),
        credentialConfigurationIdentifier: credentialConfigurationIdentifier,
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
        let cNonce,
        let cNonceExpiresIn,
        let errorDescription
      ):
        guard let cNonce = CNonce(value: cNonce, expiresInSeconds: cNonceExpiresIn) else {
          return .failure(
            ValidationError.error(
              reason: error.localizedDescription
            )
          )
        }
        
        return .success(
          .invalidProof(
            cNonce: cNonce,
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
    claimSet: ClaimSet?,
    bindingKeys: [BindingKey] = [],
    cNonce: CNonce? = nil,
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
      supportedCredential: supportedCredential,
      cNonce: cNonce
    )
    
    return try await requestIssuance(
      token: token,
      dPopNonce: authorizedRequest.dPopNonce
    ) {
      return try supportedCredential.toIssuanceRequest(
        requester: issuanceRequester,
        claimSet: claimSet, 
        proofs: proofs,
        responseEncryptionSpecProvider: responseEncryptionSpecProvider
      )
    }
  }
  
  func identifierBasedRequest(
    authorizedRequest: AuthorizedRequest,
    token: IssuanceAccessToken,
    bindingKeys: [BindingKey] = [],
    cNonce: CNonce? = nil,
    credentialIdentifier: CredentialIdentifier,
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
      supportedCredential: supportedCredential,
      cNonce: cNonce
    )
    
    return try await requestIssuance(
      token: token,
      dPopNonce: authorizedRequest.dPopNonce
    ) {
      return try supportedCredential.toIssuanceRequest(
        requester: issuanceRequester,
        proofs: proofs,
        credentialIdentifier: credentialIdentifier,
        responseEncryptionSpecProvider: responseEncryptionSpecProvider
      )
    }
  }
  
  func obtainProofs(
    authorizedRequest: AuthorizedRequest,
    batchCredentialIssuance: BatchCredentialIssuance?,
    bindingKeys: [BindingKey],
    supportedCredential: CredentialSupported,
    cNonce: CNonce?
  ) async throws -> [Proof] {
    let proofs = await (try? bindingKeys.asyncCompactMap { try await $0.toSupportedProof(
      issuanceRequester: issuanceRequester,
      credentialSpec: supportedCredential,
      cNonce: cNonce?.value
    )}) ?? []
    switch proofs.count {
    case 0:
      switch authorizedRequest {
      case .noProofRequired:
        return proofs
      case .proofRequired:
        throw ValidationError.error(reason: "At least one binding is required in AuthorizedRequest.proofRequired")
      }
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
    encryptionMethodsSupported: [JOSEEncryptionMethod]
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
      privateKey = try? KeyController.generateRSAPrivateKey()
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
      privateKey = try? KeyController.generateECDHPrivateKey()
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
  
  func requestDeferredIssuance(
    proofRequest: AuthorizedRequest,
    transactionId: TransactionId,
    dPopNonce: Nonce?
  ) async throws -> Result<DeferredCredentialIssuanceResponse, Error> {
    
    guard let token = proofRequest.accessToken else {
      throw ValidationError.error(reason: "Invalid access token")
    }
    
    return try await deferredIssuanceRequester.placeDeferredCredentialRequest(
      accessToken: token,
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
}
