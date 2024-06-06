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
    transactionCode: String?
  ) async -> Result<AuthorizedRequest, Error>
  
  func handleAuthorizationCode(
    parRequested: UnauthorizedRequest,
    authorizationCode: IssuanceAuthorization
  ) async -> Result<UnauthorizedRequest, Error>
  
  func requestAccessToken(
    authorizationCode: UnauthorizedRequest
  ) async -> Result<AuthorizedRequest, Error>
  
  func requestSingle(
    noProofRequest: AuthorizedRequest,
    requestPayload: IssuanceRequestPayload,
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> Result<SubmittedRequest, Error>
  
  func requestSingle(
    proofRequest: AuthorizedRequest,
    bindingKey: BindingKey,
    requestPayload: IssuanceRequestPayload,
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> Result<SubmittedRequest, Error>
  
  func requestDeferredIssuance(
    proofRequest: AuthorizedRequest,
    transactionId: TransactionId
  ) async throws -> Result<DeferredCredentialIssuanceResponse, Error>
  
  func notify(
    authorizedRequest: AuthorizedRequest,
    notificationId: NotificationObject
  ) async throws -> Result<Void, Error>
  
  func requestBatch(
    noProofRequest: AuthorizedRequest,
    requestPayload: [IssuanceRequestPayload],
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> Result<SubmittedRequest, Error>
  
  func requestBatch(
    proofRequest: AuthorizedRequest,
    bindingKey: BindingKey,
    requestPayload: [IssuanceRequestPayload],
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> Result<SubmittedRequest, Error>
}

public actor Issuer: IssuerType {
  
  public var deferredResponseEncryptionSpec: IssuanceResponseEncryptionSpec? = nil
  
  let authorizationServerMetadata: IdentityAndAccessManagementMetadata
  let issuerMetadata: CredentialIssuerMetadata
  let config: OpenId4VCIConfig
  
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
    case .authorizationCode(let code), .both(let code, _):
      code.issuerState
    default:
      nil
    }
    
    let (scopes, credentialConfogurationIdentifiers) = try scopesAndCredentialConfigurationIds(credentialOffer: credentialOffer)

    let authorizationServerSupportsPar = credentialOffer.authorizationServerMetadata.authorizationServerSupportsPar

    let state = StateValue().value
    
    if authorizationServerSupportsPar {
      do {
        let result: (
          verifier: PKCEVerifier,
          code: GetAuthorizationCodeURL
        ) = try await authorizer.submitPushedAuthorizationRequest(
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
              state: state
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
              state: state
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
    transactionCode: String?
  ) async -> Result<AuthorizedRequest, Error> {
    
    switch authorizationCode {
    case .preAuthorizationCode(let authorisation, let txCode):
      do {
        guard let transactionCode else {
          throw ValidationError.error(reason: "Issuer's grant is pre-authorization code with transaction code required but no transaction code passed")
        }
        
        if txCode.length != transactionCode.count {
          throw ValidationError.error(reason: "Expected transaction code length is \(txCode.length ?? 0) but code of length \(transactionCode.count) passed")
        }
        
        if txCode.inputMode != .numeric {
          throw ValidationError.error(reason: "Issuers expects transaction code to be numeric but is not.")
        }
        
        let response =
        try await authorizer.requestAccessTokenPreAuthFlow(
          preAuthorizedCode: authorisation,
          txCode: txCode,
          clientId: clientId,
          transactionCode: transactionCode
        )
        
        switch response {
        case .success((let accessToken, let nonce, let identifiers)):
          if let cNonce = nonce {
            return .success(
              .proofRequired(
                accessToken: try IssuanceAccessToken(
                  accessToken: accessToken.accessToken,
                  tokenType: accessToken.tokenType
                ),
                refreshToken: nil,
                cNonce: cNonce,
                credentialIdentifiers: identifiers
              )
            )
          } else {
            return .success(
              .noProofRequired(
                accessToken: try IssuanceAccessToken(
                  accessToken: accessToken.accessToken,
                  tokenType: accessToken.tokenType
                ),
                refreshToken: nil,
                credentialIdentifiers: identifiers
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
  
  public func requestAccessToken(authorizationCode: UnauthorizedRequest) async -> Result<AuthorizedRequest, Error> {
    switch authorizationCode {
    case .par:
      return .failure(ValidationError.error(reason: ".authorizationCode case is required"))
      
    case .authorizationCode(let request):
      switch request.authorizationCode {
      case .authorizationCode(authorizationCode: let authorizationCode):
        do {
          let response: (
            accessToken: IssuanceAccessToken,
            nonce: CNonce?,
            identifiers: AuthorizationDetailsIdentifiers?,
            tokenType: TokenType?
          ) = try await authorizer.requestAccessTokenAuthFlow(
            authorizationCode: authorizationCode,
            codeVerifier: request.pkceVerifier.codeVerifier
          ).get()
          
          if let cNonce = response.nonce {
            return .success(
              .proofRequired(
                accessToken: try IssuanceAccessToken(
                  accessToken: response.accessToken.accessToken,
                  tokenType: response.tokenType
                ),
                refreshToken: nil,
                cNonce: cNonce,
                credentialIdentifiers: response.identifiers
              )
            )
          } else {
            return .success(
              .noProofRequired(
                accessToken: try IssuanceAccessToken(
                  accessToken: response.accessToken.accessToken,
                  tokenType: response.tokenType
                ),
                refreshToken: nil,
                credentialIdentifiers: response.identifiers
              )
            )
          }
        } catch {
          return .failure(ValidationError.error(reason: error.localizedDescription))
        }
      default: return .failure(ValidationError.error(reason: ".authorizationCode case is required"))
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
              pkceVerifier: request.pkceVerifier
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
                pkceVerifier: request.pkceVerifier
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
    case .noProofRequired(let token, _, _):
      return token
    case .proofRequired(let token, _, _, _):
      return token
    }
  }
  
  private func cNonce(from request: AuthorizedRequest) -> CNonce? {
    switch request {
    case .noProofRequired:
      return nil
    case .proofRequired(_, _, let cnonce, _):
      return cnonce
    }
  }
  
  public func requestSingle(
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
        token: token, 
        claimSet: claimSet,
        credentialConfigurationIdentifier: credentialConfigurationIdentifier,
        responseEncryptionSpecProvider: responseEncryptionSpecProvider
      )
    }
  }
  
  public func requestSingle(
    proofRequest: AuthorizedRequest,
    bindingKey: BindingKey,
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
        token: token,
        bindingKey: bindingKey,
        credentialIdentifier: credentialIdentifier,
        credentialConfigurationIdentifier: credentialConfigurationIdentifier,
        responseEncryptionSpecProvider: responseEncryptionSpecProvider
      )
      
    case .configurationBased(
      let credentialConfigurationIdentifier,
      let claimSet
    ):
      return try await formatBasedRequest(
        token: token,
        claimSet: claimSet,
        bindingKey: bindingKey,
        cNonce: cNonce(from: proofRequest),
        credentialConfigurationIdentifier: credentialConfigurationIdentifier,
        responseEncryptionSpecProvider: responseEncryptionSpecProvider
      )
    }
  }
  
  public func requestBatch(
    noProofRequest: AuthorizedRequest,
    requestPayload: [IssuanceRequestPayload],
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> Result<SubmittedRequest, Error> {
    switch noProofRequest {
    case .noProofRequired(let token, _, _):
      return try await requestIssuance(token: token) {
        let credentialRequests: [CredentialIssuanceRequest] = try requestPayload.map { identifier in
          guard let supportedCredential = issuerMetadata
            .credentialsSupported[identifier.credentialConfigurationIdentifier] else {
            throw ValidationError.error(reason: "Invalid Supported credential for requestBatch")
          }
          return try supportedCredential.toIssuanceRequest(
            requester: issuanceRequester,
            claimSet: identifier.claimSet,
            responseEncryptionSpecProvider: responseEncryptionSpecProvider
          )
        }
        
        let batch: [SingleCredential] = credentialRequests.compactMap { credentialIssuanceRequest in
          switch credentialIssuanceRequest {
          case .single(let credential, _):
            return credential
          default:
            return nil
          }
        }
        return .batch(
          batch,
          deferredResponseEncryptionSpec
        )
      }
    default: return .failure(ValidationError.error(reason: ".noProofRequired is required"))
    }
  }
  
  public func requestBatch(
    proofRequest: AuthorizedRequest,
    bindingKey: BindingKey,
    requestPayload: [IssuanceRequestPayload],
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> Result<SubmittedRequest, Error> {
    switch proofRequest {
    case .proofRequired(let token, _, let cNonce, _):
      return try await requestIssuance(token: token) {
        let credentialRequests: [CredentialIssuanceRequest] = try requestPayload.map { identifier in
          guard let supportedCredential = issuerMetadata
            .credentialsSupported[identifier.credentialConfigurationIdentifier] else {
            throw ValidationError.error(reason: "Invalid Supported credential for requestBatch")
          }
          return try supportedCredential.toIssuanceRequest(
            requester: issuanceRequester,
            claimSet: identifier.claimSet,
            proof: bindingKey.toSupportedProof(
              issuanceRequester: issuanceRequester,
              credentialSpec: supportedCredential,
              cNonce: cNonce.value
            ),
            responseEncryptionSpecProvider: responseEncryptionSpecProvider
          )
        }
        
        let batch: [SingleCredential] = credentialRequests.compactMap { credentialIssuanceRequest in
          switch credentialIssuanceRequest {
          case .single(let credential, _):
            return credential
          default:
            return nil
          }
        }
        return .batch(
          batch,
          deferredResponseEncryptionSpec
        )
      }
    default: return .failure(ValidationError.error(reason: ".noProofRequired is required"))
    }
  }
}

private extension Issuer {
  
  private func requestIssuance(
    token: IssuanceAccessToken,
    issuanceRequestSupplier: () throws -> CredentialIssuanceRequest
  ) async throws -> Result<SubmittedRequest, Error> {
    let credentialRequest = try issuanceRequestSupplier()
    switch credentialRequest {
    case .single(let single, let encryptionSpec):
      self.deferredResponseEncryptionSpec = encryptionSpec
      let result = try await issuanceRequester.placeIssuanceRequest(
        accessToken: token,
        request: single
      )
      switch result {
      case .success(let response):
        return .success(.success(response: response))
      case .failure(let error):
        return handleIssuanceError(error)
      }
    case .batch(let credentials, let encryptionSpec):
      self.deferredResponseEncryptionSpec = encryptionSpec
      let result = try await issuanceRequester.placeBatchIssuanceRequest(
        accessToken: token,
        request: credentials
      )
      switch result {
      case .success(let response):
        return .success(
          .success(
            response: response
          )
        )
      case .failure(let error):
        throw ValidationError.error(reason: error.localizedDescription)
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
    token: IssuanceAccessToken,
    claimSet: ClaimSet?,
    bindingKey: BindingKey? = nil,
    cNonce: CNonce? = nil,
    credentialConfigurationIdentifier: CredentialConfigurationIdentifier,
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> Result<SubmittedRequest, Error> {
      
    guard let supportedCredential = issuerMetadata
      .credentialsSupported[credentialConfigurationIdentifier] else {
      throw ValidationError.error(reason: "Invalid Supported credential for requestSingle")
    }
    
    return try await requestIssuance(token: token) {
      return try supportedCredential.toIssuanceRequest(
        requester: issuanceRequester,
        claimSet: claimSet, 
        proof: bindingKey?.toSupportedProof(
          issuanceRequester: issuanceRequester,
          credentialSpec: supportedCredential,
          cNonce: cNonce?.value
        ),
        responseEncryptionSpecProvider: responseEncryptionSpecProvider
      )
    }
  }
  
  func identifierBasedRequest(
    token: IssuanceAccessToken,
    bindingKey: BindingKey? = nil,
    cNonce: CNonce? = nil,
    credentialIdentifier: CredentialIdentifier,
    credentialConfigurationIdentifier: CredentialConfigurationIdentifier,
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> Result<SubmittedRequest, Error> {
    
    guard let supportedCredential = issuerMetadata
      .credentialsSupported[credentialConfigurationIdentifier] else {
      throw ValidationError.error(reason: "Invalid Supported credential for requestSingle")
    }
    
    return try await requestIssuance(token: token) {
      return try supportedCredential.toIssuanceRequest(
        requester: issuanceRequester,
        proof: bindingKey?.toSupportedProof(
          issuanceRequester: issuanceRequester,
          credentialSpec: supportedCredential,
          cNonce: cNonce?.value
        ),
        credentialIdentifier: credentialIdentifier,
        responseEncryptionSpecProvider: responseEncryptionSpecProvider
      )
    }
  }
}

public extension Issuer {
  
  static func createResponseEncryptionSpec(_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec? {
    switch issuerResponseEncryptionMetadata {
    case .notRequired:
      return Self.createResponseEncryptionSpecFrom(algorithmsSupported: [.init(.RSA_OAEP_256)], encryptionMethodsSupported: [.init(.A128CBC_HS256)])
    case let .required(algorithmsSupported, encryptionMethodsSupported):
      return Self.createResponseEncryptionSpecFrom(algorithmsSupported: algorithmsSupported, encryptionMethodsSupported: encryptionMethodsSupported)
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
    transactionId: TransactionId
  ) async throws -> Result<DeferredCredentialIssuanceResponse, Error> {
    
    guard let token = proofRequest.accessToken else {
      throw ValidationError.error(reason: "Invalid access token")
    }
    
    return try await deferredIssuanceRequester.placeDeferredCredentialRequest(
      accessToken: token,
      transactionId: transactionId,
      issuanceResponseEncryptionSpec: deferredResponseEncryptionSpec
    )
  }
  
  func notify(
    authorizedRequest: AuthorizedRequest,
    notificationId: NotificationObject
  ) async throws -> Result<Void, Error> {
    
    return try await notifyIssuer.notify(
      authorizedRequest: authorizedRequest,
      notification: notificationId
    )
  }
}
