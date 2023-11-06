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
}

public actor Issuer: IssuerType {
  
  let authorizationServerMetadata: AuthorizationServerMetadata
  let issuerMetadata: CredentialIssuerMetadata
  let config: WalletOpenId4VCIConfig
  
  private let authorizer: IssuanceAuthorizerType
  private let requester: IssuanceRequesterType
  
  public init(
    authorizationServerMetadata: AuthorizationServerMetadata,
    issuerMetadata: CredentialIssuerMetadata,
    config: WalletOpenId4VCIConfig
  ) {
    self.authorizationServerMetadata = authorizationServerMetadata
    self.issuerMetadata = issuerMetadata
    self.config = config
    
    authorizer = IssuanceAuthorizer(
      config: config,
      parEndpoint: URL(string: "")!,
      authorizationEndpoint: URL(string: "")!,
      redirectionURI: URL(string: "")!,
      clientId: "clientId"
    )
    
    requester = IssuanceRequester(
      issuerMetadata: issuerMetadata
    )
  }
  
  public func pushAuthorizationCodeRequest(
    credentials: [CredentialMetadata],
    issuerState: String?
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
        default:
          return nil
        }
      }
    let state = UUID().uuidString
    do {
      let result: (verifier: PKCEVerifier, code: GetAuthorizationCodeURL) = try await authorizer.submitPushedAuthorizationRequest(scopes: scopes, state: state, issuerState: issuerState).get()
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
      return .failure(ValidationError.error(reason: "Invalid issuance authorisation, pre authorisation supported only"))
      
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
  
  func requestSingle(
    noProofRequest: AuthorizedRequest,
    credentialMetadata: CredentialMetadata,
    claimSet: ClaimSet?
  ) async -> Result<SubmittedRequest, Error> {
    switch noProofRequest {
    case .noProofRequired(let token):
      //      requestIssuance(token) {
      //        credentialMetadata
      //          .toIssuerSupportedCredential()
      //          .toIssuanceRequest(claimSet, null)
      //      }
      return .failure(ValidationError.error(reason: ""))
    default: return .failure(ValidationError.error(reason: ".noProofRequired is required"))
    }
  }
}

private extension Issuer {
  
    private func toIssuerSupportedCredential(metaData: CredentialMetadata) throws -> CredentialSupported {
      switch metaData {
      case .scope:
        return try supportedCredentialByScope(metaData: requester.issuerMetadata, scoped: metaData)
      default:
        throw ValidationError.error(reason: "")// requester.issuerMetadata.supportedCredentialByProfile(this)
      }
    }
  
  private func supportedCredentialByScope(
    metaData: CredentialIssuerMetadata,
    scoped: CredentialMetadata
  ) throws -> CredentialSupported {
    switch scoped {
    case .scope(let byScope):
      return try metaData.credentialsSupported.first { element in
        return element.scope == byScope.value
      } ?? { throw ValidationError.error(reason: "Issuer does not support issuance of credential scope: \(byScope)") }()
    default: throw ValidationError.error(reason: "")
    }
  }
}
