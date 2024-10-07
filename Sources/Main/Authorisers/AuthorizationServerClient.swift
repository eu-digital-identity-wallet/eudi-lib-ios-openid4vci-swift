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
import SwiftyJSON

let OPENID_CREDENTIAL = "openid_credential"

public protocol AuthorizationServerClientType {
  
  func authorizationRequestUrl(
    scopes: [Scope],
    credentialConfigurationIdentifiers: [CredentialConfigurationIdentifier],
    state: String,
    issuerState: String?
  ) async throws -> Result<(PKCEVerifier, GetAuthorizationCodeURL), Error>
  
  func submitPushedAuthorizationRequest(
    scopes: [Scope],
    credentialConfigurationIdentifiers: [CredentialConfigurationIdentifier],
    state: String,
    issuerState: String?,
    resource: String?
  ) async throws -> Result<(PKCEVerifier, GetAuthorizationCodeURL), Error>
  
  func requestAccessTokenAuthFlow(
    authorizationCode: String,
    codeVerifier: String
  ) async throws -> Result<(IssuanceAccessToken, CNonce?, AuthorizationDetailsIdentifiers?, TokenType?, Int?), ValidationError>
  
  func requestAccessTokenPreAuthFlow(
    preAuthorizedCode: String,
    txCode: TxCode?,
    clientId: String,
    transactionCode: String?
  ) async throws -> Result<(IssuanceAccessToken, CNonce?, AuthorizationDetailsIdentifiers?, Int?), ValidationError>
}

public actor AuthorizationServerClient: AuthorizationServerClientType {
  
  public let config: OpenId4VCIConfig
  public let service: AuthorisationServiceType
  public let parPoster: PostingType
  public let tokenPoster: PostingType
  public let parEndpoint: URL?
  public let authorizationEndpoint: URL
  public let tokenEndpoint: URL
  public let redirectionURI: URL
  public let clientId: String
  public let authorizationServerMetadata: IdentityAndAccessManagementMetadata
  public let credentialIssuerIdentifier: CredentialIssuerId
  public let dpopConstructor: DPoPConstructorType?
  
  static let responseType = "code"
  static let grantAuthorizationCode = "authorization_code"
  static let grantPreauthorizationCode = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
  
  public init(
    service: AuthorisationServiceType = AuthorisationService(),
    parPoster: PostingType = Poster(),
    tokenPoster: PostingType = Poster(),
    config: OpenId4VCIConfig,
    authorizationServerMetadata: IdentityAndAccessManagementMetadata,
    credentialIssuerIdentifier: CredentialIssuerId,
    dpopConstructor: DPoPConstructorType? = nil
  ) throws {
    self.service = service
    self.parPoster = parPoster
    self.tokenPoster = tokenPoster
    self.config = config
    
    self.authorizationServerMetadata = authorizationServerMetadata
    self.credentialIssuerIdentifier = credentialIssuerIdentifier
    
    self.redirectionURI = config.authFlowRedirectionURI
    self.clientId = ClientId(config.clientId)
    
    self.dpopConstructor = dpopConstructor
    
    switch authorizationServerMetadata {
    case .oidc(let data):
      
      if let tokenEndpoint = data.tokenEndpoint, let url = URL(string: tokenEndpoint) {
        self.tokenEndpoint = url
      } else {
        throw ValidationError.error(reason: "Invalid token endpoint")
      }
      
      if let authorizationEndpoint = data.authorizationEndpoint, let url = URL(string: authorizationEndpoint) {
        self.authorizationEndpoint = url
      } else {
        throw ValidationError.error(reason: "In valid authorization endpoint")
      }
      
      if let pushedAuthorizationRequestEndpoint = data.pushedAuthorizationRequestEndpoint, let url = URL(string: pushedAuthorizationRequestEndpoint) {
        self.parEndpoint = url
      } else {
        self.parEndpoint = nil
      }
      
    case .oauth(let data):
      
      if let tokenEndpoint = data.tokenEndpoint, let url = URL(string: tokenEndpoint) {
        self.tokenEndpoint = url
      } else {
        throw ValidationError.error(reason: "Invalid token endpoint")
      }
      
      if let authorizationEndpoint = data.authorizationEndpoint, let url = URL(string: authorizationEndpoint) {
        self.authorizationEndpoint = url
      } else {
        throw ValidationError.error(reason: "In valid authorization endpoint")
      }
      
      if let pushedAuthorizationRequestEndpoint = data.pushedAuthorizationRequestEndpoint, let url = URL(string: pushedAuthorizationRequestEndpoint) {
        self.parEndpoint = url
      } else {
        self.parEndpoint = nil
      }
    }
  }
  
  public func authorizationRequestUrl(
    scopes: [Scope],
    credentialConfigurationIdentifiers: [CredentialConfigurationIdentifier],
    state: String,
    issuerState: String?
  ) async throws -> Result<(PKCEVerifier, GetAuthorizationCodeURL), Error> {
    guard !scopes.isEmpty else {
      throw ValidationError.error(reason: "No scopes provided. Cannot submit par with no scopes.")
    }
    
    let codeVerifier = PKCEGenerator.codeVerifier() ?? ""
    let verifier = try PKCEVerifier(
      codeVerifier: codeVerifier,
      codeVerifierMethod: CodeChallenge.sha256.rawValue
    )
    
    let authzRequest = AuthorizationRequest(
      responseType: Self.responseType,
      clientId: config.clientId,
      redirectUri: config.authFlowRedirectionURI.absoluteString,
      scope: scopes.map { $0.value }.joined(separator: " ").appending(" ").appending(Constants.OPENID_SCOPE),
      credentialConfigurationIds: toAuthorizationDetail(credentialConfigurationIds: credentialConfigurationIdentifiers),
      state: state,
      codeChallenge: PKCEGenerator.generateCodeChallenge(codeVerifier: codeVerifier),
      codeChallengeMethod: CodeChallenge.sha256.rawValue,
      issuerState: issuerState
    )
    
    guard let urlWithParams = authorizationEndpoint.appendingQueryParameters(
      try authzRequest.toDictionary().convertToDictionaryOfStrings(
        excludingKeys: [
          "credential_configuration_ids",
          "code_challenge",
          "code_challenge_method"
        ]
      )
    ) else {
      throw ValidationError.invalidUrl(parEndpoint?.absoluteString ?? "")
    }
    
    let authorizationCodeURL = try GetAuthorizationCodeURL(
      urlString: urlWithParams.absoluteString
    )
    
    return .success((verifier, authorizationCodeURL))
  }
  
  public func submitPushedAuthorizationRequest(
    scopes: [Scope],
    credentialConfigurationIdentifiers: [CredentialConfigurationIdentifier],
    state: String,
    issuerState: String?,
    resource: String? = nil
  ) async throws -> Result<(PKCEVerifier, GetAuthorizationCodeURL), Error> {
    guard !scopes.isEmpty else {
      throw ValidationError.error(reason: "No scopes provided. Cannot submit par with no scopes.")
    }
    
    let codeVerifier = PKCEGenerator.codeVerifier() ?? ""
    let authzRequest = AuthorizationRequest(
      responseType: Self.responseType,
      clientId: config.clientId,
      redirectUri: config.authFlowRedirectionURI.absoluteString,
      scope: scopes.map { $0.value }.joined(separator: " "),
      credentialConfigurationIds: toAuthorizationDetail(credentialConfigurationIds: credentialConfigurationIdentifiers),
      state: state,
      codeChallenge: PKCEGenerator.generateCodeChallenge(codeVerifier: codeVerifier),
      codeChallengeMethod: CodeChallenge.sha256.rawValue,
      resource: resource,
      issuerState: issuerState
    )
    
    do {
      guard let parEndpoint = parEndpoint else {
        throw ValidationError.error(reason: "Missing PAR endpoint")
      }
      let response: PushedAuthorizationRequestResponse = try await service.formPost(
        poster: parPoster,
        url: parEndpoint,
        request: authzRequest
      )
      
      switch response {
      case .success(let requestURI, _):
        
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
      return .failure(error)
    }
  }
  
  public func requestAccessTokenAuthFlow(
    authorizationCode: String,
    codeVerifier: String
  ) async throws -> Result<(
    IssuanceAccessToken,
    CNonce?,
    AuthorizationDetailsIdentifiers?,
    TokenType?,
    Int?
  ), ValidationError> {
    
    let parameters: [String: String] = authCodeFlow(
      authorizationCode: authorizationCode,
      redirectionURI: redirectionURI,
      clientId: clientId,
      codeVerifier: codeVerifier
    )

    let response: AccessTokenRequestResponse = try await service.formPost(
      poster: tokenPoster,
      url: tokenEndpoint, 
      headers: try tokenEndPointHeaders(),
      parameters: parameters
    )
    
    switch response {
    case .success(let tokenType, let accessToken, _, let expiresIn, _, let nonce, _, let identifiers):
      return .success(
        (
          try .init(accessToken: accessToken, tokenType: .init(value: tokenType)),
          .init(value: nonce),
          identifiers,
          TokenType(value: tokenType),
          expiresIn
        )
      )
    case .failure(let error, let errorDescription):
      throw CredentialIssuanceError.pushedAuthorizationRequestFailed(
        error: error,
        errorDescription: errorDescription
      )
    }
  }
  
  public func requestAccessTokenPreAuthFlow(
    preAuthorizedCode: String,
    txCode: TxCode?,
    clientId: String,
    transactionCode: String?
  ) async throws -> Result<(IssuanceAccessToken, CNonce?, AuthorizationDetailsIdentifiers?, Int?), ValidationError> {
    let parameters: JSON = try await preAuthCodeFlow(
      preAuthorizedCode: preAuthorizedCode,
      txCode: txCode,
      clientId: clientId,
      transactionCode: transactionCode
    )
    
    let response: AccessTokenRequestResponse = try await service.formPost(
      poster: tokenPoster,
      url: tokenEndpoint,
      headers: try tokenEndPointHeaders(),
      parameters: parameters.toDictionary().convertToDictionaryOfStrings()
    )
    
    switch response {
    case .success(let tokenType, let accessToken, _, let expiresIn, _, let nonce, _, let identifiers):
      return .success(
        (
          try .init(accessToken: accessToken, tokenType: .init(value: tokenType)),
          .init(value: nonce),
          identifiers,
          expiresIn
        )
      )
    case .failure(let error, let errorDescription):
      throw CredentialIssuanceError.pushedAuthorizationRequestFailed(
        error: error,
        errorDescription: errorDescription
      )
    }
  }
  
  func toAuthorizationDetail(
    credentialConfigurationIds: [CredentialConfigurationIdentifier]
  ) -> [AuthorizationDetail] {
    credentialConfigurationIds.compactMap { id in
      var locations: [String] = []
      if credentialIssuerIdentifier.url.absoluteString != authorizationServerMetadata.issuer {
        locations.append(credentialIssuerIdentifier.url.absoluteString)
      }
      
      return AuthorizationDetail(
        type: .init(type: OPENID_CREDENTIAL),
        locations: locations,
        credentialConfigurationId: id.value
      )
    }
  }
}

private extension AuthorizationServerClient {
  
  func tokenEndPointHeaders() throws -> [String: String] {
    if let dpopConstructor {
      return ["DPoP": try dpopConstructor.jwt(endpoint: tokenEndpoint, accessToken: nil)]
    } else {
      return [:]
    }
  }
  
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
    txCode: TxCode?,
    clientId: String,
    transactionCode: String?
  ) async throws -> JSON  {
    if txCode != nil {
      let dictionary: [String: Any?] = [
        Constants.CLIENT_ID_PARAM: clientId,
        Constants.GRANT_TYPE_PARAM: Constants.GRANT_TYPE_PARAM_VALUE,
        Constants.PRE_AUTHORIZED_CODE_PARAM: preAuthorizedCode,
        Constants.TX_CODE_PARAM: transactionCode
      ].filter { $0.value != nil }
      return JSON(dictionary)
      
    } else {
      return [
        Constants.CLIENT_ID_PARAM: clientId,
        Constants.GRANT_TYPE_PARAM: Constants.GRANT_TYPE_PARAM_VALUE,
        Constants.PRE_AUTHORIZED_CODE_PARAM: preAuthorizedCode
      ]
    }
  }
}
