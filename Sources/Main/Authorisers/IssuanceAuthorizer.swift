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

public actor IssuanceAuthorizer {
  
  let config: WalletOpenId4VCIConfig
  let service: AuthorisationServiceType
  let poster: Posting
  
  public init(
    service: AuthorisationServiceType = AuthorisationService(),
    poster: Posting = Poster(),
    config: WalletOpenId4VCIConfig
  ) {
    self.service = service
    self.poster = poster
    self.config = config
  }
  
  func submitPushedAuthorizationRequest(
    scopes: [String],
    state: String,
    issuerState: String?
  ) async throws -> Result<(PKCEVerifier, GetAuthorizationCodeURL), Error> {
    let authzRequest = AuthorizationRequest(
      responseType: "code",
      redirectUri: config.authFlowRedirectionURI.absoluteString,
      scope: scopes.joined(separator: " "),
      state: state,
      codeChallenge: PKCEGenerator.generateRandomBase64String(),
      issuerState: issuerState
    )
    
    do {
      let url = URL(string: "")!
      let response: PushedAuthorizationRequestResponse = try await service.formPost(
        poster: poster,
        url: url,
        request: authzRequest
      )
      
      let verifier = try PKCEVerifier(codeVerifier: "", codeVerifierMethod: "")
      
      let queryParams = [
        GetAuthorizationCodeURL.PARAM_CLIENT_ID: "value1",
        GetAuthorizationCodeURL.PARAM_REQUEST_URI: "value2"
      ]
      
      guard let urlWithParams = url.appendingQueryParameters(queryParams) else {
        throw ValidationError.invalidUrl("")
      }
      
      let authorizationCodeURL = try GetAuthorizationCodeURL(
        urlString: urlWithParams.absoluteString
      )
      
      return .success((verifier, authorizationCodeURL))
      
    } catch {
      return .failure(ValidationError.nonHttpsUrl(""))
    }
  }
  
  func requestAccessTokenAuthFlow(
    authorizationCode: String,
    codeVerifier: String,
    redirectionURI: URL,
    clientId: String
  ) async throws -> Result<String, ValidationError> {
    
    let parameters: [String: String] = authCodeFlow(
      authorizationCode: authorizationCode,
      redirectionURI: redirectionURI,
      clientId: clientId,
      codeVerifier: codeVerifier
    )
    
    let url = URL(string: "")!
    let response: AccessTokenRequestResponse = try await service.formPost(
      poster: poster,
      url: url,
      parameters: parameters
    )

    switch response {
    case .success(let accessToken, let expiresIn, let scope):
      return .success(accessToken)
    case .failure(let error, let errorDescription):
      return .failure(ValidationError.nonHttpsUrl(""))
    }
  }
  
  func requestAccessTokenPreAuthFlow(
    preAuthorizedCode: String,
    userPin: String
  ) async throws -> Result<String, ValidationError> {
    let parameters: [String: String] = try preAuthCodeFlow(
      preAuthorizedCode: preAuthorizedCode,
      userPin: userPin
    )
    
    let url = URL(string: "")!
    let response: AccessTokenRequestResponse = try await service.formPost(
      poster: poster,
      url: url,
      parameters: parameters
    )

    switch response {
    case .success(let accessToken, let expiresIn, let scope):
      return .success(accessToken)
    case .failure(let error, let errorDescription):
      return .failure(ValidationError.nonHttpsUrl(""))
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
    
    let grantValue = "authorization_code"
    let params: [String: String] = [
      Constants.GRANT_TYPE_PARAM: grantValue,
      Constants.AUTHORIZATION_CODE_PARAM: authorizationCode,
      Constants.REDIRECT_URI_PARAM: redirectionURI.absoluteString,
      Constants.CLIENT_ID_PARAM: clientId,
      Constants.CODE_VERIFIER_PARAM: codeVerifier,
    ]
    
    return params
  }
  
  func preAuthCodeFlow(
    preAuthorizedCode: String,
    userPin: String
  ) throws -> [String: String]  {
    
    let grantValue = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    let params: [String: String] = [
      Constants.GRANT_TYPE_PARAM: try grantValue.utf8UrlEncoded(),
      Constants.PRE_AUTHORIZED_CODE_PARAM: preAuthorizedCode,
      Constants.USER_PIN_PARAM: userPin
    ]
    
    return params
  }
}
