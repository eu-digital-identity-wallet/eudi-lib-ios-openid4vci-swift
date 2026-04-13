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

protocol AuthorizeIssuanceType: Sendable {
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
  ///   - grant: Grants used to authorize the request.
  ///   - request: The request that needs authorization.
  ///   - authorizationCode: The unauthorized request containing the authorization code.
  ///   - authorizationDetailsInTokenRequest: Additional authorization details for the token request.
  /// - Returns: A result containing either an `AuthorizedRequest` if successful or an `Error` otherwise.
  func authorizeWithAuthorizationCode(
    grant: Grants,
    request: AuthorizationRequested,
    authorizationCode: AuthorizationCode,
    authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest
  ) async throws -> AuthorizedRequest
}

internal actor AuthorizeIssuance: AuthorizeIssuanceType {
  
  let config: OpenId4VCIConfig
  let authorizer: AuthorizationServerClientType
  let challenger: ChallengeEndpointClientType?
  let issuerMetadata: CredentialIssuerMetadata
  
  init(
    config: OpenId4VCIConfig,
    authorizer: AuthorizationServerClientType,
    challenger: ChallengeEndpointClientType?,
    issuerMetadata: CredentialIssuerMetadata
  ) {
    self.config = config
    self.authorizer = authorizer
    self.challenger = challenger
    self.issuerMetadata = issuerMetadata
  }
  
  func prepareAuthorizationRequest(
    credentialOffer: CredentialOffer
  ) async throws -> AuthorizationRequested {
    
    let issuerState: String? = getIssuerState(from: credentialOffer)
    let (scopes, identifiers) = try scopesAndCredentialConfigurationIds(
      credentialOffer: credentialOffer
    )
    
    let authorizationServerSupportsPar = credentialOffer.authorizationServerMetadata.authorizationServerSupportsPar && config.requirePAR
    
    if config.requirePAR {
      guard let _ = credentialOffer.authorizationServerMetadata.pushedAuthorizationRequestEndpointURI else {
        throw ValidationError.parRequired
      }
    }
    
    let state = StateValue().value
    
    if authorizationServerSupportsPar {
      return try await handlePARAuthorization(
        credentialOffer: credentialOffer,
        scopes: scopes,
        credentialConfigurationIdentifiers: identifiers,
        issuerState: issuerState,
        state: state
      )
      
    } else {
      return try await handleStandardAuthorization(
        scopes: scopes,
        credentialConfigurationIdentifiers: credentialOffer.credentialConfigurationIdentifiers,
        issuerState: issuerState,
        state: state
      )
    }
  }
  
  func authorizeWithPreAuthorizationCode(
    credentialOffer: CredentialOffer,
    authorizationCode: IssuanceAuthorization,
    client: Client,
    transactionCode: String?,
    authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest
  ) async throws -> AuthorizedRequest {
    switch authorizationCode {
    case .preAuthorizationCode(let authorisation, let txCode):
        if let transactionCode, let txCode {
          if txCode.length != transactionCode.count {
            throw ValidationError.error(
              reason: "Expected transaction code length is \(txCode.length ?? 0) but code of length \(transactionCode.count) passed"
            )
          }
        }
        
        let credConfigIdsAsAuthDetails: [CredentialConfigurationIdentifier] = switch authorizationDetailsInTokenRequest {
        case .doNotInclude: []
        case .include(let filter): credentialOffer.credentialConfigurationIdentifiers.filter(filter)
        }
        
        let challenge = try? await challenger?.getChallenge()
        let (
            accessToken,
            refreshToken,
            identifiers,
            expiresIn,
            dPopNonce
          ) = try await authorizer.requestAccessTokenPreAuthFlow(
          preAuthorizedCode: authorisation,
          txCode: txCode,
          client: client,
          transactionCode: transactionCode,
          identifiers: credConfigIdsAsAuthDetails,
          dpopNonce: nil,
          challenge: challenge,
          maxRetries: Constants.MAX_RETRIES
        )
        
          return AuthorizedRequest(
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
              dPopNonce: dPopNonce,
              grantType: .init(grant: credentialOffer.grants)
            )
    default:
      throw ValidationError.error(
        reason: "Invalid issuance authorisation, pre authorisation supported only"
      )
    }
  }
  
  func authorizeWithAuthorizationCode(
    grant: Grants,
    request: AuthorizationRequested,
    authorizationCode: AuthorizationCode,
    authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest
  ) async throws -> AuthorizedRequest {
          let credConfigIdsAsAuthDetails: [CredentialConfigurationIdentifier] = switch authorizationDetailsInTokenRequest {
          case .doNotInclude: []
          case .include(let filter): request.configurationIds.filter(filter)
          }
          
          let challenge = try? await challenger?.getChallenge()
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
            challenge: challenge,
            maxRetries: Constants.MAX_RETRIES
          )
          
          return AuthorizedRequest(
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
              dPopNonce: response.dPopNonce,
              grantType: .init(grant: grant)
            )
  }
}

private extension AuthorizeIssuance {
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
          scopes.append(
            try Scope(
              scope
            )
          )
        } else {
          configurationIdentifiers.append(id)
        }
      case .authorizationDetails:
        configurationIdentifiers.append(id)
      }
    }
    return (scopes, configurationIdentifiers)
  }
  
  private func getIssuerState(from offer: CredentialOffer) -> String? {
    switch offer.grants {
    case .authorizationCode(let code),
         .both(let code, _):
      return code.issuerState
    default:
      return nil
    }
  }
  
  private func handlePARAuthorization(
    credentialOffer: CredentialOffer,
    scopes: [Scope],
    credentialConfigurationIdentifiers: [CredentialConfigurationIdentifier],
    issuerState: String?,
    state: String
  ) async throws -> AuthorizationRequested {
      let resource: String? = issuerMetadata.authorizationServers.map { _ in
        credentialOffer.credentialIssuerIdentifier.url.absoluteString
      }

      let challenge = try? await challenger?.getChallenge()
      
      let result: (
        verifier: PKCEVerifier,
        code: AuthorizationCodeURL,
        dPopNonce: Nonce?
      ) = try await authorizer.submitPushedAuthorizationRequest(
        scopes: scopes,
        credentialConfigurationIdentifiers: credentialConfigurationIdentifiers,
        state: state,
        issuerState: issuerState,
        resource: resource,
        dpopNonce: nil,
        challenge: challenge,
        maxRetries: Constants.MAX_RETRIES
      )

      return AuthorizationRequested(
            credentials: try credentialConfigurationIdentifiers.map {
              try CredentialIdentifier(value: $0.value)
            },
            authorizationCodeURL: result.code,
            pkceVerifier: result.verifier,
            state: state,
            configurationIds: credentialConfigurationIdentifiers,
            dpopNonce: result.dPopNonce
        )
  }
  
  private func handleStandardAuthorization(
    scopes: [Scope],
    credentialConfigurationIdentifiers: [CredentialConfigurationIdentifier],
    issuerState: String?,
    state: String
  ) async throws -> AuthorizationRequested {
      let result: (
        verifier: PKCEVerifier,
        code: AuthorizationCodeURL
      ) = try await authorizer.authorizationRequestUrl(
        scopes: scopes,
        credentialConfigurationIdentifiers: credentialConfigurationIdentifiers,
        state: state,
        issuerState: issuerState
      )

      return AuthorizationRequested(
            credentials: try credentialConfigurationIdentifiers.map {
                try CredentialIdentifier(value: $0.value)
            },
            authorizationCodeURL: result.code,
            pkceVerifier: result.verifier,
            state: state,
            configurationIds: credentialConfigurationIdentifiers
        )
  }
}
