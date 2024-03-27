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
  ) async -> Result<UnauthorizedRequest, Error>
  
  func authorizeWithPreAuthorizationCode(
    credentials: [CredentialIdentifier],
    authorizationCode: IssuanceAuthorization
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
    claimSet: ClaimSet?,
    requestCredentialIdentifier: IssuanceRequestCredentialIdentifier,
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> Result<SubmittedRequest, Error>
  
  func requestSingle(
    proofRequest: AuthorizedRequest,
    bindingKey: BindingKey,
    claimSet: ClaimSet?,
    requestCredentialIdentifier: IssuanceRequestCredentialIdentifier,
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
}

public actor Issuer: IssuerType {
  
  let authorizationServerMetadata: IdentityAndAccessManagementMetadata
  let issuerMetadata: CredentialIssuerMetadata
  let config: WalletOpenId4VCIConfig
  
  private let authorizer: IssuanceAuthorizerType
  
  private let issuanceRequester: IssuanceRequesterType
  private let deferredIssuanceRequester: IssuanceRequesterType
  
  private let notifyIssuer: NotifyIssuerType
  
  public init(
    authorizationServerMetadata: IdentityAndAccessManagementMetadata,
    issuerMetadata: CredentialIssuerMetadata,
    config: WalletOpenId4VCIConfig,
    parPoster: PostingType = Poster(),
    tokenPoster: PostingType = Poster(),
    requesterPoster: PostingType = Poster(),
    deferredRequesterPoster: PostingType = Poster(),
    notificationPoster: PostingType = Poster()
  ) throws {
    self.authorizationServerMetadata = authorizationServerMetadata
    self.issuerMetadata = issuerMetadata
    self.config = config
    
    authorizer = try IssuanceAuthorizer(
      parPoster: parPoster,
      tokenPoster: tokenPoster,
      config: config,
      authorizationServerMetadata: authorizationServerMetadata
    )
    
    issuanceRequester = IssuanceRequester(
      issuerMetadata: issuerMetadata, 
      poster: requesterPoster
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
  ) async -> Result<UnauthorizedRequest, Error> {
    let credentials = credentialOffer.credentialConfigurationIdentifiers
    let issuerState: String? = switch credentialOffer.grants {
    case .authorizationCode(let code), .both(let code, _):
      code.issuerState
    default:
      nil
    }

    var authorizationDetails: [OidCredentialAuthorizationDetail] = []
    var scopes: [Scope] = []
    
    credentialOffer.credentialConfigurationIdentifiers.forEach { credentialConfigurationId in
      if let credentialConfigurationIdentifier = try? CredentialConfigurationIdentifier(value: credentialConfigurationId.value),
         let supportedCredential = issuerMetadata.credentialsSupported[credentialConfigurationIdentifier],
           let scope = try? Scope(supportedCredential.getScope()) {
          scopes.append(scope)
        } else {
          authorizationDetails.append(ByCredentialConfiguration(credentialConfigurationId: credentialConfigurationId))
        }
    }
    
    let authorizationServerSupportsPar = credentialOffer.authorizationServerMetadata.authorizationServerSupportsPar

    let state = String.randomBase64URLString(length: 32)
    
    if authorizationServerSupportsPar {
      do {
        let result: (
          verifier: PKCEVerifier,
          code: GetAuthorizationCodeURL
        ) = try await authorizer.submitPushedAuthorizationRequest(
          scopes: scopes,
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
      return .failure(ValidationError.error(reason: "Authorization server does not support PAR"))
    }
  }
  
  public func authorizeWithPreAuthorizationCode(
    credentials: [CredentialIdentifier],
    authorizationCode: IssuanceAuthorization
  ) async -> Result<AuthorizedRequest, Error> {
    switch authorizationCode {
    case .authorizationCode:
      return .failure(ValidationError.error(
        reason: "Invalid issuance authorisation, pre authorisation supported only"
      ))
      
    case .preAuthorizationCode(let authorisation, let pin):
      do {
        let response =
        try await authorizer.requestAccessTokenPreAuthFlow(
          preAuthorizedCode: authorisation,
          userPin: pin
        )
        
        switch response {
        case .success((let accessToken, let nonce)):
          if let cNonce = CNonce(value: nonce) {
            return .success(.proofRequired(token: try IssuanceAccessToken(accessToken: accessToken), cNonce: cNonce, credentialIdentifiers: [:]))
          } else {
            return .success(.noProofRequired(token: try IssuanceAccessToken(accessToken: accessToken), credentialIdentifiers: [:]))
          }
        case .failure(let error):
          return .failure(ValidationError.error(reason: error.localizedDescription))
        }
      } catch {
        return .failure(ValidationError.error(reason: error.localizedDescription))
      }
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
            accessToken: String,
            nonce: String?
          ) = try await authorizer.requestAccessTokenAuthFlow(
            authorizationCode: authorizationCode,
            codeVerifier: request.pkceVerifier.codeVerifier
          ).get()
          
          if let nonce = response.nonce, let cNonce = CNonce(value: nonce) {
            return .success(
              .proofRequired(
                token: try IssuanceAccessToken(accessToken: response.accessToken),
                cNonce: cNonce,
                credentialIdentifiers: [:]
              )
            )
          } else {
            return .success(
              .noProofRequired(
                token: try IssuanceAccessToken(accessToken: response.accessToken),
                credentialIdentifiers: [:]
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
    case .noProofRequired(let token, _):
      return token
    case .proofRequired(let token, _, _):
      return token
    }
  }
  
  private func cNonce(from request: AuthorizedRequest) -> CNonce? {
    switch request {
    case .noProofRequired:
      return nil
    case .proofRequired(_, let cnonce, _):
      return cnonce
    }
  }
  
  public func requestSingle(
    noProofRequest: AuthorizedRequest,
    claimSet: ClaimSet? = nil,
    requestCredentialIdentifier: IssuanceRequestCredentialIdentifier,
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> Result<SubmittedRequest, Error> {
    
    guard let supportedCredential = issuerMetadata
      .credentialsSupported[requestCredentialIdentifier.0] else {
      throw ValidationError.error(reason: "Invalid Supported credential for requestSingle")
    }
    
    switch noProofRequest {
    case .noProofRequired(let token, _):
      return try await requestIssuance(token: token) {
        return try supportedCredential.toIssuanceRequest(
          requester: issuanceRequester,
          claimSet: claimSet,
          responseEncryptionSpecProvider: responseEncryptionSpecProvider
        )
      }
    default: return .failure(ValidationError.error(reason: ".noProofRequired is required"))
    }
  }
  
  public func requestSingle(
    proofRequest: AuthorizedRequest,
    bindingKey: BindingKey,
    claimSet: ClaimSet? = nil,
    requestCredentialIdentifier: IssuanceRequestCredentialIdentifier,
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) async throws -> Result<SubmittedRequest, Error> {
    
    guard let supportedCredential = issuerMetadata
      .credentialsSupported[requestCredentialIdentifier.0] else {
      throw ValidationError.error(reason: "Invalid Supported credential for requestSingle")
    }
    
    let cNonce = cNonce(from: proofRequest)
    return try await requestIssuance(token: accessToken(from: proofRequest)) {
      return try supportedCredential.toIssuanceRequest(
        requester: issuanceRequester,
        claimSet: claimSet,
        proof: bindingKey.toSupportedProof(
          issuanceRequester: issuanceRequester,
          credentialSpec: supportedCredential,
          cNonce: cNonce?.value
        ),
        responseEncryptionSpecProvider: responseEncryptionSpecProvider
      )
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
    case .single(let single):
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
    case .batch(let credentials):
      let result = try await issuanceRequester.placeBatchIssuanceRequest(
        accessToken: token,
        request: credentials
      )
      switch result {
      case .success(let response):
        return .success(.success(response: response))
      case .failure(let error):
        throw ValidationError.error(reason: error.localizedDescription)
      }
    }
  }
}

private extension Issuer {
  
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
      transactionId: transactionId
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
