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

public protocol IssuanceAuthorizerType {
  
  func submitPushedAuthorizationRequest(
    scopes: [Scope],
    state: String,
    issuerState: String?
  ) async throws -> Result<(PKCEVerifier, GetAuthorizationCodeURL), Error>
  
  func requestAccessTokenAuthFlow(
    authorizationCode: String,
    codeVerifier: String
  ) async throws -> Result<(String, String?), ValidationError>
  
  func requestAccessTokenPreAuthFlow(
    preAuthorizedCode: String,
    userPin: String
  ) async throws -> Result<(String, String?), ValidationError>
}

public actor IssuanceAuthorizer: IssuanceAuthorizerType {
  
  let config: WalletOpenId4VCIConfig
  
  let service: AuthorisationServiceType
  let poster: PostingType
  
  let parEndpoint: URL
  let authorizationEndpoint: URL

  let redirectionURI: URL
  let clientId: String
  
  static let responseType = "code"
  static let grantAuthorizationCode = "authorization_code"
  static let grantPreauthorizationCode = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
  
  public init(
    service: AuthorisationServiceType = AuthorisationService(),
    poster: PostingType = Poster(),
    config: WalletOpenId4VCIConfig,
    parEndpoint: URL,
    authorizationEndpoint: URL,
    redirectionURI: URL,
    clientId: String
  ) {
    self.service = service
    self.poster = poster
    self.config = config
    self.parEndpoint = parEndpoint
    self.authorizationEndpoint = authorizationEndpoint
    self.redirectionURI = redirectionURI
    self.clientId = clientId
  }
  
  public func submitPushedAuthorizationRequest(
    scopes: [Scope],
    state: String,
    issuerState: String?
  ) async throws -> Result<(PKCEVerifier, GetAuthorizationCodeURL), Error> {
    guard !scopes.isEmpty else {
      throw ValidationError.error(reason: "No scopes provided. Cannot submit par with no scopes.")
    }
    
    let authzRequest = AuthorizationRequest(
      responseType: Self.responseType,
      clientId: config.clientId,
      redirectUri: config.authFlowRedirectionURI.absoluteString,
      scope: scopes.map { $0.value }.joined(separator: " "),
      state: state,
      codeChallenge: PKCEGenerator.generateRandomBase64String(),
      issuerState: issuerState
    )
    
    do {
      let response: PushedAuthorizationRequestResponse = try await service.formPost(
        poster: poster,
        url: parEndpoint,
        request: authzRequest
      )
      
      switch response {
      case .success(requestURI: let requestURI, _):
        guard let codeVerifier = PKCEGenerator.codeVerifier() else {
          throw ValidationError.error(reason: "Unable to generate code verifier")
        }
        
        let verifier = try PKCEVerifier(
          codeVerifier: codeVerifier,
          codeVerifierMethod: CodeChallenge.sha256.rawValue
        )
        
        let queryParams = [
          GetAuthorizationCodeURL.PARAM_CLIENT_ID: config.clientId,
          GetAuthorizationCodeURL.PARAM_REQUEST_STATE: state,
          GetAuthorizationCodeURL.PARAM_REQUEST_URI: requestURI
        ]
        
        guard let urlWithParams = parEndpoint.appendingQueryParameters(queryParams) else {
          throw ValidationError.invalidUrl(parEndpoint.absoluteString)
        }
        
        let authorizationCodeURL = try GetAuthorizationCodeURL(
          urlString: urlWithParams.absoluteString
        )
        
        return .success((verifier, authorizationCodeURL))
        
      case .failure(error: let error, errorDescription: let errorDescription):
        throw CredentialIssuanceError.pushedAuthorizationRequestFailed(
          error: error,
          errorDescription: errorDescription
        )
      }
    } catch {
      return .failure(ValidationError.error(reason: error.localizedDescription))
    }
  }
  
  public func requestAccessTokenAuthFlow(
    authorizationCode: String,
    codeVerifier: String
  ) async throws -> Result<(String, String?), ValidationError> {
    
    let parameters: [String: String] = authCodeFlow(
      authorizationCode: authorizationCode,
      redirectionURI: redirectionURI,
      clientId: clientId,
      codeVerifier: codeVerifier
    )
    
    let response: AccessTokenRequestResponse = try await service.formPost(
      poster: poster,
      url: authorizationEndpoint,
      parameters: parameters
    )
    
    switch response {
    case .success(let accessToken, _, _, let nonce, _):
      return .success((accessToken, nonce))
    case .failure(let error, let errorDescription):
      throw CredentialIssuanceError.pushedAuthorizationRequestFailed(
        error: error,
        errorDescription: errorDescription
      )
    }
  }
  
  public func requestAccessTokenPreAuthFlow(
    preAuthorizedCode: String,
    userPin: String
  ) async throws -> Result<(String, String?), ValidationError> {
    let parameters: [String: String] = try preAuthCodeFlow(
      preAuthorizedCode: preAuthorizedCode,
      userPin: userPin
    )
    
    let response: AccessTokenRequestResponse = try await service.formPost(
      poster: poster,
      url: authorizationEndpoint,
      parameters: parameters
    )
    
    switch response {
    case .success(let accessToken, _, _, let nonce, _):
      return .success((accessToken, nonce))
    case .failure(let error, let errorDescription):
      throw CredentialIssuanceError.pushedAuthorizationRequestFailed(
        error: error,
        errorDescription: errorDescription
      )
    }
  }
}

private extension IssuanceAuthorizer {
  
  func authCodeFlow(
    authorizationCode: String,
    redirectionURI: URL,
    clientId: String,
    codeVerifier: String
  ) -> [String: String]  {
    
    [
      Constants.GRANT_TYPE_PARAM: Self.grantAuthorizationCode,
      Constants.AUTHORIZATION_CODE_PARAM: authorizationCode,
      Constants.REDIRECT_URI_PARAM: redirectionURI.absoluteString,
      Constants.CLIENT_ID_PARAM: clientId,
      Constants.CODE_VERIFIER_PARAM: codeVerifier,
    ]
  }
  
  func preAuthCodeFlow(
    preAuthorizedCode: String,
    userPin: String
  ) throws -> [String: String]  {
    [
      Constants.GRANT_TYPE_PARAM: try Self.grantPreauthorizationCode.utf8UrlEncoded(),
      Constants.PRE_AUTHORIZED_CODE_PARAM: preAuthorizedCode,
      Constants.USER_PIN_PARAM: userPin
    ]
  }
}
