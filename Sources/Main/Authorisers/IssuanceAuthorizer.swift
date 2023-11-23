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
  
  public let config: WalletOpenId4VCIConfig
  public let service: AuthorisationServiceType
  public let parPoster: PostingType
  public let tokenPoster: PostingType
  public let parEndpoint: URL
  public let authorizationEndpoint: URL
  public let tokenEndpoint: URL
  public let redirectionURI: URL
  public let clientId: String
  public let authorizationServerMetadata: IdentityAndAccessManagementMetadata
  
  static let responseType = "code"
  static let grantAuthorizationCode = "authorization_code"
  static let grantPreauthorizationCode = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
  
  public init(
    service: AuthorisationServiceType = AuthorisationService(),
    parPoster: PostingType = Poster(),
    tokenPoster: PostingType = Poster(),
    config: WalletOpenId4VCIConfig,
    authorizationServerMetadata: IdentityAndAccessManagementMetadata
  ) throws {
    self.service = service
    self.parPoster = parPoster
    self.tokenPoster = tokenPoster
    self.config = config
    self.authorizationServerMetadata = authorizationServerMetadata
    self.redirectionURI = config.authFlowRedirectionURI
    self.clientId = ClientId(config.clientId)
    
    switch authorizationServerMetadata {
    case .oidc(let data):
      
      if let url = URL(string: data.tokenEndpoint) {
        self.tokenEndpoint = url
      } else {
        throw ValidationError.error(reason: "Invalid token endpoint")
      }
      
      if let url = URL(string: data.authorizationEndpoint) {
        self.authorizationEndpoint = url
      } else {
        throw ValidationError.error(reason: "In valid authorization endpoint")
      }
      
      if let url = URL(string: data.pushedAuthorizationRequestEndpoint) {
        self.parEndpoint = url
      } else {
        throw ValidationError.error(reason: "In valid authorization endpoint")
      }
    case .oauth(let data):
      
      if let url = URL(string: data.tokenEndpoint) {
        self.tokenEndpoint = url
      } else {
        throw ValidationError.error(reason: "Invalid token endpoint")
      }
      
      if let url = URL(string: data.pushedAuthorizationRequestEndpoint) {
        self.authorizationEndpoint = url
      } else {
        throw ValidationError.error(reason: "In valid authorization endpoint")
      }
      
      if let url = URL(string: data.pushedAuthorizationRequestEndpoint) {
        self.parEndpoint = url
      } else {
        throw ValidationError.error(reason: "In valid pushed authorization request endpoint")
      }
    }
  }
  
  public func submitPushedAuthorizationRequest(
    scopes: [Scope],
    state: String,
    issuerState: String?
  ) async throws -> Result<(PKCEVerifier, GetAuthorizationCodeURL), Error> {
    guard !scopes.isEmpty else {
      throw ValidationError.error(reason: "No scopes provided. Cannot submit par with no scopes.")
    }
    
    let codeVerifier = PKCEGenerator.codeVerifier() ?? ""
    let authzRequest = AuthorizationRequest(
      responseType: Self.responseType,
      clientId: config.clientId,
      redirectUri: config.authFlowRedirectionURI.absoluteString,
      scope: scopes.map { $0.value }.joined(separator: " ").appending(" openid"),
      state: state,
      codeChallenge: PKCEGenerator.generateCodeChallenge(codeVerifier: codeVerifier),
      codeChallengeMethod: CodeChallenge.sha256.rawValue,
      issuerState: issuerState
    )
    
    do {
      let response: PushedAuthorizationRequestResponse = try await service.formPost(
        poster: parPoster,
        url: parEndpoint,
        request: authzRequest
      )
      
      switch response {
      case .success(requestURI: let requestURI, _):
        
        let verifier = try PKCEVerifier(
          codeVerifier: codeVerifier,
          codeVerifierMethod: CodeChallenge.sha256.rawValue
        )
        
        let queryParams = [
          GetAuthorizationCodeURL.PARAM_CLIENT_ID: config.clientId,
          GetAuthorizationCodeURL.PARAM_REQUEST_STATE: state,
          GetAuthorizationCodeURL.PARAM_REQUEST_URI: requestURI
        ]
        
        guard let urlWithParams = authorizationEndpoint.appendingQueryParameters(queryParams) else {
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
      poster: tokenPoster,
      url: tokenEndpoint, 
      headers: [:],
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
      poster: tokenPoster,
      url: authorizationEndpoint,
      headers: [:],
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
    userPin: String?
  ) throws -> [String: String]  {
    if let userPin {
      [
        Constants.GRANT_TYPE_PARAM: try Self.grantPreauthorizationCode.utf8UrlEncoded(),
        Constants.PRE_AUTHORIZED_CODE_PARAM: preAuthorizedCode,
        Constants.USER_PIN_PARAM: userPin
      ]
    } else {
      [
        Constants.GRANT_TYPE_PARAM: try Self.grantPreauthorizationCode.utf8UrlEncoded(),
        Constants.PRE_AUTHORIZED_CODE_PARAM: preAuthorizedCode
      ]
    }
  }
}
