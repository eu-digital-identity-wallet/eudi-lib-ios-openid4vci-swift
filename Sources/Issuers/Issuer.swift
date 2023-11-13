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

public protocol IssuerType {
  
  func pushAuthorizationCodeRequest(
    credentials: [CredentialMetadata],
    issuerState: String?
  ) async -> Result<UnauthorizedRequest, Error>
  
  func authorizeWithPreAuthorizationCode(
    credentials: [CredentialMetadata],
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
    authorizedRequest: AuthorizedRequest,
    credentialMetadata: CredentialMetadata?,
    claimSet: ClaimSet?
  ) async throws -> Result<SubmittedRequest, Error>
  
  func requestSingle(
    noProofRequest: AuthorizedRequest,
    credentialMetadata: CredentialMetadata,
    claimSet: ClaimSet?
  ) async throws -> Result<SubmittedRequest, Error>
  
  func requestSingle(
    proofRequest: AuthorizedRequest,
    credentialMetadata: CredentialMetadata?,
    bindingKey: BindingKey,
    claimSet: ClaimSet?
  ) async throws -> Result<SubmittedRequest, Error>
}

public actor Issuer: IssuerType {

  let authorizationServerMetadata: IdentityAndAccessManagementMetadata
  let issuerMetadata: CredentialIssuerMetadata
  let config: WalletOpenId4VCIConfig
  
  private let authorizer: IssuanceAuthorizerType
  private let requester: IssuanceRequesterType
  
  public init(
    authorizationServerMetadata: IdentityAndAccessManagementMetadata,
    issuerMetadata: CredentialIssuerMetadata,
    config: WalletOpenId4VCIConfig
  ) throws {
    self.authorizationServerMetadata = authorizationServerMetadata
    self.issuerMetadata = issuerMetadata
    self.config = config
    
    authorizer = try IssuanceAuthorizer(
      config: config,
      authorizationServerMetadata: authorizationServerMetadata
    )
    
    requester = IssuanceRequester(
      issuerMetadata: issuerMetadata
    )
  }
  
  public func pushAuthorizationCodeRequest(
    credentials: [CredentialMetadata],
    issuerState: String? = nil
  ) async -> Result<UnauthorizedRequest, Error> {
    let scopes: [Scope] = credentials
      .filter {
        if case .scope = $0 {
          return true
        }
        return false
      }
      .compactMap { metaData in
        switch metaData {
        case .scope(let scope):
          return scope
        default: return nil
        }
      }
    let state = UUID().uuidString
    do {
      let result: (verifier: PKCEVerifier, code: GetAuthorizationCodeURL) = try await authorizer.submitPushedAuthorizationRequest(
        scopes: scopes,
        state: state,
        issuerState: issuerState
      ).get()
      return .success(
        .par(
          .init(
            credentials: credentials,
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
  
  public func authorizeWithPreAuthorizationCode(
    credentials: [CredentialMetadata],
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
            return .success(.proofRequired(token: try IssuanceAccessToken(accessToken: accessToken), cNonce: cNonce))
          } else {
            return .success(.noProofRequired(token: try IssuanceAccessToken(accessToken: accessToken)))
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
          let response: (accessToken: String, nonce: String?) = try await authorizer.requestAccessTokenAuthFlow(
            authorizationCode: authorizationCode,
            codeVerifier: request.pkceVerifier.codeVerifier
          ).get()
          
          if let nonce = response.nonce, let cNonce = CNonce(value: nonce) {
            return .success(
              .proofRequired(
                token: try IssuanceAccessToken(accessToken: response.accessToken),
                cNonce: cNonce
              )
            )
          } else {
            return .success(
              .noProofRequired(
                token: try IssuanceAccessToken(accessToken: response.accessToken)
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
    authorizationCode: IssuanceAuthorization
  ) async -> Result<UnauthorizedRequest, Error> {
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
    case .noProofRequired(let token):
      return token
    case .proofRequired(let token, _):
      return token
    }
  }
  
  public func requestSingle(
    noProofRequest: AuthorizedRequest,
    credentialMetadata: CredentialMetadata,
    claimSet: ClaimSet?
  ) async throws -> Result<SubmittedRequest, Error> {
    switch noProofRequest {
    case .noProofRequired(let token):
      return try await requestIssuance(token: token) {
        switch credentialMetadata {
        case .scope:
          return try supportedCredentialByScope(
            metaData: requester.issuerMetadata,
            scoped: credentialMetadata
          )?.toIssuanceRequest(claimSet: claimSet) ?? {
            throw ValidationError.error(reason: "Invalid scope \(#function)")
          }()
        case .msoMdoc, 
             .w3CSignedJwt,
             .w3CJsonLdSignedJwt,
             .w3CJsonLdDataIntegrity,
             .sdJwtVc:
          return try supportedCredentialByProfile(
            metaData: requester.issuerMetadata,
            profile: credentialMetadata
          )?.toIssuanceRequest(claimSet: claimSet) ?? {
            throw ValidationError.error(reason: "Invalid scope \(#function)")
          }()
        }
      }
    default: return .failure(ValidationError.error(reason: ".noProofRequired is required"))
    }
  }
  
  public func requestSingle(
    authorizedRequest: AuthorizedRequest,
    credentialMetadata: CredentialMetadata?,
    claimSet: ClaimSet? = nil
  ) async throws -> Result<SubmittedRequest, Error> {
    
    guard let credentialMetadata else {
      throw ValidationError.error(reason: "Invalid credential CredentialMetadata for requestSingle")
    }
    
    return try await requestIssuance(token: accessToken(from: authorizedRequest)) {
      switch credentialMetadata {
      case .scope:
        return try supportedCredentialByScope(
          metaData: requester.issuerMetadata,
          scoped: credentialMetadata
        )!.toIssuanceRequest(claimSet: claimSet)
        
      case .msoMdoc,
           .w3CSignedJwt,
           .w3CJsonLdSignedJwt,
           .w3CJsonLdDataIntegrity,
           .sdJwtVc:
        return try supportedCredentialByProfile(
          metaData: requester.issuerMetadata,
          profile: credentialMetadata
        )?.toIssuanceRequest(claimSet: claimSet) ?? {
          throw ValidationError.error(reason: "Invalid scope \(#function)")
        }()
      }
    }
  }
  
  public func requestSingle(
    proofRequest: AuthorizedRequest,
    credentialMetadata: CredentialMetadata?,
    bindingKey: BindingKey,
    claimSet: ClaimSet? = nil
  ) async throws -> Result<SubmittedRequest, Error> {
    
    guard let credentialMetadata else {
      throw ValidationError.error(reason: "Invalid credential CredentialMetadata for requestSingle")
    }
    
    return try await requestIssuance(token: accessToken(from: proofRequest)) {
      switch credentialMetadata {
      case .scope:
        return try supportedCredentialByScope(
          metaData: requester.issuerMetadata,
          scoped: credentialMetadata
        )!.toIssuanceRequest(claimSet: claimSet)
      case .msoMdoc,
           .w3CSignedJwt,
           .w3CJsonLdSignedJwt,
           .w3CJsonLdDataIntegrity,
           .sdJwtVc:
        return try supportedCredentialByProfile(
          metaData: requester.issuerMetadata,
          profile: credentialMetadata
        )?.toIssuanceRequest(claimSet: claimSet) ?? {
          throw ValidationError.error(reason: "Invalid scope \(#function)")
        }()
      }
    }
  }
}

private extension Issuer {
  
  private func supportedCredentialByScope(
    metaData: CredentialIssuerMetadata,
    scoped: CredentialMetadata
  ) throws -> SupportedCredential? {
    switch scoped {
    case .scope(let byScope):
      return try metaData.credentialsSupported.first { element in
        switch element {
        case .scope(let scope):
          return scope.value == byScope.value
        default: return false
        }
      } ?? { throw ValidationError.error(reason: "Issuer does not support issuance of credential scope: \(byScope)") }()
    default: throw ValidationError.error(reason: "")
    }
  }
  
  private func supportedCredentialByProfile(
    metaData: CredentialIssuerMetadata,
    profile: CredentialMetadata
  ) throws -> SupportedCredential? {
    switch profile {
    case .msoMdoc(let profile):
      return metaData.credentialsSupported.first { supportedCredential in
        switch supportedCredential {
        case .msoMdoc(let credential):
          return credential.docType == profile.docType
        default: return false
        }
      }
    case .w3CJsonLdDataIntegrity(let profile):
      return metaData.credentialsSupported.first { supportedCredential in
        switch supportedCredential {
        case .w3CJsonLdDataIntegrity(let credential):
          return credential.credentialDefinition.context == profile.credentialDefinition.type &&
          credential.credentialDefinition.context == profile.credentialDefinition.type
        default: return false
        }
      }
    case .w3CJsonLdSignedJwt(let profile):
      return metaData.credentialsSupported.first { supportedCredential in
        switch supportedCredential {
        case .w3CJsonLdDataIntegrity(let credential):
          return credential.credentialDefinition.context == profile.credentialDefinition.context &&
          credential.credentialDefinition.type == profile.credentialDefinition.type
        default: return false
        }
      }
    case .w3CSignedJwt(let profile):
      return metaData.credentialsSupported.first { supportedCredential in
        switch supportedCredential {
        case .w3CJsonLdDataIntegrity(let credential):
          return credential.credentialDefinition.type == profile.credentialDefinition.type
        default: return false
        }
      }
    case .sdJwtVc:
      throw ValidationError.error(reason: "TODO")
    default: throw ValidationError.error(reason: "Scope not supported for \(#function)")
    }
  }
  
  private func requestIssuance(
    token: IssuanceAccessToken,
    issuanceRequestSupplier: () throws -> CredentialIssuanceRequest
  ) async throws -> Result<SubmittedRequest, Error> {
    let credentialRequest = try issuanceRequestSupplier()
    switch credentialRequest {
    case .single(let single):
      let result = await requester.placeIssuanceRequest(
        accessToken: token,
        request: single
      )
      switch result {
      case .success(let response):
        return .success(.success(response: response))
      case .failure(let error):
        throw ValidationError.error(reason: error.localizedDescription)
      }
    case .batch(let credentials):
      let result = try await requester.placeBatchIssuanceRequest(
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
