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

private extension ResponseWithHeaders {
  func dpopNonce() -> Nonce? {
    if let nonceValue = headers.value(forCaseInsensitiveKey: Constants.DPOP_NONCE_HEADER) as? String {
      return Nonce(value: nonceValue)
    }
    return nil
  }
}

/// A protocol defining the interface for an authorization server client.
/// This client is responsible for handling authorization requests, token exchanges, and refresh flows.
protocol AuthorizationServerClientType: Sendable {
  
  /// Generates a URL for initiating the authorization request.
  ///
  /// - Parameters:
  ///   - scopes: The requested authorization scopes.
  ///   - credentialConfigurationIdentifiers: Identifiers for the credential configurations.
  ///   - state: A unique state parameter
  ///   - issuerState: Optional issuer-specific state parameter.
  /// - Returns: A result containing a `PKCEVerifier` and an authorization URL, or an error if the operation fails.
  func authorizationRequestUrl(
    scopes: [Scope],
    credentialConfigurationIdentifiers: [CredentialConfigurationIdentifier],
    state: String,
    issuerState: String?
  ) async throws -> Result<(PKCEVerifier, AuthorizationCodeURL), Error>
  
  /// Submits a pushed authorization request (PAR).
  ///
  /// - Parameters:
  ///   - scopes: The requested authorization scopes.
  ///   - credentialConfigurationIdentifiers: Identifiers for the credential configurations.
  ///   - state: A unique state parameter
  ///   - issuerState: Optional issuer-specific state parameter.
  ///   - resource: An optional resource identifier.
  ///   - dpopNonce: An optional nonce for DPoP (Demonstrating Proof-of-Possession).
  ///   - retry: A flag indicating whether to retry on failure.
  /// - Returns: A result containing a `PKCEVerifier`, an authorization URL, and an optional nonce, or an error if the operation fails.
  /// See [RFC7636](https://www.rfc-editor.org/rfc/rfc7636.html) for more information
  /// See [RFC9126](https://www.rfc-editor.org/rfc/rfc9126) for more information
  func submitPushedAuthorizationRequest(
    scopes: [Scope],
    credentialConfigurationIdentifiers: [CredentialConfigurationIdentifier],
    state: String,
    issuerState: String?,
    resource: String?,
    dpopNonce: Nonce?,
    retry: Bool
  ) async throws -> Result<(PKCEVerifier, AuthorizationCodeURL, Nonce?), Error>
  
  /// Requests an access token using an authorization code.
  ///
  /// - Parameters:
  ///   - authorizationCode: The authorization code received from the authorization server.
  ///   - codeVerifier: The PKCE code verifier.
  ///   - identifiers: Identifiers for the credential configurations.
  ///   - dpopNonce: An optional nonce for DPoP.
  ///   - retry: A flag indicating whether to retry on failure.
  /// - Returns: A result containing the access token, refresh token, authorization details, token type, expiration time, and an optional nonce, or an error if the operation fails.
  func requestAccessTokenAuthFlow(
    authorizationCode: String,
    codeVerifier: String,
    identifiers: [CredentialConfigurationIdentifier],
    dpopNonce: Nonce?,
    retry: Bool
  ) async throws -> Result<(
    IssuanceAccessToken,
    IssuanceRefreshToken,
    AuthorizationDetailsIdentifiers?,
    TokenType?,
    Int?,
    Nonce?
  ), Error>
  
  /// Requests an access token using a pre-authorized code.
  ///
  /// - Parameters:
  ///   - preAuthorizedCode: The pre-authorized code provided by the authorization server.
  ///   - txCode: An optional transaction code.
  ///   - client: The client making the request.
  ///   - transactionCode: An optional transaction code string.
  ///   - identifiers: Identifiers for the credential configurations.
  ///   - dpopNonce: An optional nonce for DPoP.
  ///   - retry: A flag indicating whether to retry on failure.
  /// - Returns: A result containing the access token, refresh token, authorization details, expiration time, and an optional nonce, or an error if the operation fails.
  func requestAccessTokenPreAuthFlow(
    preAuthorizedCode: String,
    txCode: TxCode?,
    client: Client,
    transactionCode: String?,
    identifiers: [CredentialConfigurationIdentifier],
    dpopNonce: Nonce?,
    retry: Bool
  ) async throws -> Result<(
    IssuanceAccessToken,
    IssuanceRefreshToken,
    AuthorizationDetailsIdentifiers?,
    Int?,
    Nonce?
  ), Error>
  
  /// Refreshes an access token using a refresh token.
  ///
  /// - Parameters:
  ///   - clientId: The client ID used for authentication.
  ///   - refreshToken: The refresh token issued previously.
  ///   - dpopNonce: An optional nonce for DPoP.
  ///   - retry: A flag indicating whether to retry on failure.
  /// - Returns: A result containing the new access token, authorization details, token type, expiration time, and an optional nonce, or an error if the operation fails.
  func refreshAccessToken(
    clientId: String,
    refreshToken: IssuanceRefreshToken,
    dpopNonce: Nonce?,
    retry: Bool
  ) async throws -> Result<(
    IssuanceAccessToken,
    AuthorizationDetailsIdentifiers?,
    TokenType?,
    Int?,
    Nonce?
  ), Error>
}

internal actor AuthorizationServerClient: AuthorizationServerClientType {
  
  public let config: OpenId4VCIConfig
  public let service: AuthorisationServiceType
  public let parPoster: PostingType
  public let tokenPoster: PostingType
  public let parEndpoint: URL?
  public let authorizationEndpoint: URL
  public let tokenEndpoint: URL
  public let redirectionURI: URL
  public let client: Client
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
    self.client = config.client
    
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
        throw ValidationError.error(reason: "Invalid authorization endpoint")
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
  ) async throws -> Result<(PKCEVerifier, AuthorizationCodeURL), Error> {
    let scopesAreValid = scopes.isEmpty == false
    let identifiersAreValid = credentialConfigurationIdentifiers.isEmpty == false

    guard scopesAreValid || identifiersAreValid else {
      throw ValidationError.error(
        reason: "Both scopes and credential configuration identifiers are missing or empty. Cannot submit par"
      )
    }
    
    let codeVerifier = PKCEGenerator.codeVerifier() ?? ""
    let verifier = try PKCEVerifier(
      codeVerifier: codeVerifier,
      codeVerifierMethod: CodeChallenge.sha256.rawValue
    )
    
    let authzRequest = AuthorizationRequest(
      responseType: Self.responseType,
      clientId: config.client.id,
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
          "credential_configuration_ids"
        ]
      )
    ) else {
      throw ValidationError.invalidUrl(parEndpoint?.absoluteString ?? "")
    }
    
    let authorizationCodeURL = try AuthorizationCodeURL(
      urlString: urlWithParams.absoluteString
    )
    
    return .success((verifier, authorizationCodeURL))
  }
  
  public func submitPushedAuthorizationRequest(
    scopes: [Scope],
    credentialConfigurationIdentifiers: [CredentialConfigurationIdentifier],
    state: String,
    issuerState: String?,
    resource: String? = nil,
    dpopNonce: Nonce? = nil,
    retry: Bool = true
  ) async throws -> Result<(PKCEVerifier, AuthorizationCodeURL, Nonce?), Error> {
    
    let scopesAreValid = scopes.isEmpty == false
    let identifiersAreValid = credentialConfigurationIdentifiers.isEmpty == false

    guard scopesAreValid || identifiersAreValid else {
      throw ValidationError.error(
        reason: "Both scopes and credential configuration identifiers are missing or empty. Cannot submit par"
      )
    }
    
    let codeVerifier = PKCEGenerator.codeVerifier() ?? ""
    let authRequest: AuthorizationRequest = .init(
      responseType: Self.responseType,
      clientId: config.client.id,
      redirectUri: config.authFlowRedirectionURI.absoluteString,
      scope: scopes.map { $0.value }.joined(separator: " "),
      credentialConfigurationIds: toAuthorizationDetail(
        credentialConfigurationIds: credentialConfigurationIdentifiers
      ),
      state: state,
      codeChallenge: PKCEGenerator.generateCodeChallenge(
        codeVerifier: codeVerifier
      ),
      codeChallengeMethod: CodeChallenge.sha256.rawValue,
      resource: resource,
      issuerState: issuerState
    )
    
    do {
      guard let parEndpoint = parEndpoint else {
        throw ValidationError.error(
          reason: "Missing PAR endpoint"
        )
      }
      
      let clientAttestationHeaders = clientAttestationHeaders(
        clientAttestation: try generateClientAttestationIfNeeded(
          clock: Clock(),
          authServerId: URL(
            string: authorizationServerMetadata.issuer ?? ""
          )
        )
      )
      
      let tokenHeaders = try await tokenEndPointHeaders(
        url: parEndpoint,
        dpopNonce: dpopNonce
      )
      
      let response: ResponseWithHeaders<PushedAuthorizationRequestResponse> = try await service.formPost(
        poster: parPoster,
        url: parEndpoint,
        request: authRequest,
        headers: clientAttestationHeaders + tokenHeaders
      )
      
      switch response.body {
      case .success(let requestURI, _):
        let verifier = try PKCEVerifier(
          codeVerifier: codeVerifier,
          codeVerifierMethod: CodeChallenge.sha256.rawValue
        )
        
        let queryParams = [
          AuthorizationCodeURL.PARAM_CLIENT_ID: config.client.id,
          AuthorizationCodeURL.PARAM_REQUEST_STATE: state,
          AuthorizationCodeURL.PARAM_REQUEST_URI: requestURI
        ]
        
        guard let urlWithParams = authorizationEndpoint.appendingQueryParameters(queryParams) else {
          throw ValidationError.invalidUrl(parEndpoint.absoluteString)
        }
        
        let authorizationCodeURL = try AuthorizationCodeURL(
          urlString: urlWithParams.absoluteString
        )
        
        return .success(
          (verifier, authorizationCodeURL, response.dpopNonce())
        )
        
      case .failure(let error, let errorDescription):
        throw CredentialIssuanceError.pushedAuthorizationRequestFailed(
          error: error,
          errorDescription: errorDescription
        )
      }
    } catch {
      if let postError = error as? PostError {
        switch postError {
        case .useDpopNonce(let nonce):
          if retry {
            return try await submitPushedAuthorizationRequest(
              scopes: scopes,
              credentialConfigurationIdentifiers: credentialConfigurationIdentifiers,
              state: state,
              issuerState: issuerState,
              dpopNonce: nonce,
              retry: false
            )
          } else {
            return .failure(ValidationError.retryFailedAfterDpopNonce)
          }
        default:
          return .failure(error)
        }
      } else {
        return .failure(error)
      }
    }
  }
  
  public func requestAccessTokenAuthFlow(
    authorizationCode: String,
    codeVerifier: String,
    identifiers: [CredentialConfigurationIdentifier],
    dpopNonce: Nonce?,
    retry: Bool
  ) async throws -> Result<(
    IssuanceAccessToken,
    IssuanceRefreshToken,
    AuthorizationDetailsIdentifiers?,
    TokenType?,
    Int?,
    Nonce?
  ), Error> {
    
    let parameters: JSON = authCodeFlow(
      authorizationCode: authorizationCode,
      redirectionURI: redirectionURI,
      clientId: client.id,
      codeVerifier: codeVerifier,
      identifiers: identifiers
    )
    
    do {
      let clientAttestationHeaders = clientAttestationHeaders(
        clientAttestation: try generateClientAttestationIfNeeded(
          clock: Clock(),
          authServerId: URL(
            string: authorizationServerMetadata.issuer ?? ""
          )
        )
      )
      
      let tokenHeaders = try await tokenEndPointHeaders(
        url: tokenEndpoint,
        dpopNonce: dpopNonce
      )
      
      let response: ResponseWithHeaders<AccessTokenRequestResponse> = try await service.formPost(
        poster: tokenPoster,
        url: tokenEndpoint,
        headers: clientAttestationHeaders + tokenHeaders,
        parameters: parameters.toDictionary().convertToDictionaryOfStrings()
      )
      
      switch response.body {
      case .success(let tokenType, let accessToken, let refreshToken, let expiresIn, _, let identifiers):
        return .success(
          (
            try .init(
              accessToken: accessToken,
              tokenType: .init(
                value: tokenType
              )
            ),
            try .init(
              refreshToken: refreshToken
            ),
            identifiers,
            TokenType(
              value: tokenType
            ),
            expiresIn,
            response.dpopNonce()
          )
        )
      case .failure(let error, let errorDescription):
        throw CredentialIssuanceError.pushedAuthorizationRequestFailed(
          error: error,
          errorDescription: errorDescription
        )
      }
    } catch {
      if let postError = error as? PostError {
        switch postError {
        case .useDpopNonce(let nonce):
          if retry {
            return try await requestAccessTokenAuthFlow(
              authorizationCode: authorizationCode,
              codeVerifier: codeVerifier,
              identifiers: identifiers,
              dpopNonce: nonce,
              retry: false
            )
          } else {
            return .failure(ValidationError.retryFailedAfterDpopNonce)
          }
        case .networkError:
            return try await requestAccessTokenAuthFlow(
                authorizationCode: authorizationCode,
                codeVerifier: codeVerifier,
                identifiers: identifiers,
                dpopNonce: dpopNonce,
                retry: false
            )
        default:
          return .failure(error)
        }
      } else {
        return .failure(error)
      }
    }
  }
  
  public func refreshAccessToken(
    clientId: String,
    refreshToken: IssuanceRefreshToken,
    dpopNonce: Nonce?,
    retry: Bool
  ) async throws -> Result<(
    IssuanceAccessToken,
    AuthorizationDetailsIdentifiers?,
    TokenType?,
    Int?,
    Nonce?
  ), Error> {
    
    let parameters: JSON = JSON([
      Constants.CLIENT_ID_PARAM: clientId,
      Constants.GRANT_TYPE_PARAM: Constants.REFRESH_TOKEN,
      Constants.REFRESH_TOKEN_PARAM: refreshToken.refreshToken
    ].compactMapValues { $0 })
    
    do {
      let response: ResponseWithHeaders<AccessTokenRequestResponse> = try await service.formPost(
        poster: tokenPoster,
        url: tokenEndpoint,
        headers: try tokenEndPointHeaders(
          url: tokenEndpoint,
          dpopNonce: dpopNonce
        ),
        parameters: parameters.toDictionary().convertToDictionaryOfStrings()
      )
      
      switch response.body {
      case .success(
        let tokenType,
        let accessToken,
        _,
        let expiresIn,
        _,
        let identifiers
      ):
        return .success(
          (
            try .init(
              accessToken: accessToken,
              tokenType: .init(
                value: tokenType
              ),
              expiresIn: TimeInterval(expiresIn)
            ),
            identifiers,
            TokenType(
              value: tokenType
            ),
            expiresIn,
            response.dpopNonce()
          )
        )
      case .failure(let error, let errorDescription):
        throw CredentialIssuanceError.pushedAuthorizationRequestFailed(
          error: error,
          errorDescription: errorDescription
        )
      }
    } catch {
      if let postError = error as? PostError {
        switch postError {
        case .useDpopNonce(let nonce):
          if retry {
            return try await refreshAccessToken(
              clientId: clientId,
              refreshToken: refreshToken,
              dpopNonce: nonce,
              retry: false
            )
          } else {
            return .failure(ValidationError.retryFailedAfterDpopNonce)
          }
        default:
          return .failure(error)
        }
      } else {
        return .failure(error)
      }
    }
  }
  
  public func requestAccessTokenPreAuthFlow(
    preAuthorizedCode: String,
    txCode: TxCode?,
    client: Client,
    transactionCode: String?,
    identifiers: [CredentialConfigurationIdentifier],
    dpopNonce: Nonce?,
    retry: Bool
  ) async throws -> Result<(
    IssuanceAccessToken,
    IssuanceRefreshToken,
    AuthorizationDetailsIdentifiers?,
    Int?,
    Nonce?
  ), Error> {
      let parameters: JSON = try await preAuthCodeFlow(
        preAuthorizedCode: preAuthorizedCode,
        txCode: txCode,
        client: client,
        transactionCode: transactionCode,
        identifiers: identifiers
      )
      
      do {
        let clientAttestationHeaders = clientAttestationHeaders(
          clientAttestation: try generateClientAttestationIfNeeded(
            clock: Clock(),
            authServerId: URL(
              string: authorizationServerMetadata.issuer ?? ""
            )
          )
        )
        
        let tokenHeaders = try await tokenEndPointHeaders(
          url: tokenEndpoint,
          dpopNonce: dpopNonce
        )
        
        let response: ResponseWithHeaders<AccessTokenRequestResponse> = try await service.formPost(
          poster: tokenPoster,
          url: tokenEndpoint,
          headers: clientAttestationHeaders + tokenHeaders,
          parameters: parameters.toDictionary().convertToDictionaryOfStrings()
        )
        
        switch response.body {
        case .success(let tokenType, let accessToken, let refreshToken, let expiresIn, _, let identifiers):
          return .success(
            (
              try .init(
                accessToken: accessToken,
                tokenType: .init(
                  value: tokenType
                )
              ),
              try .init(
                refreshToken: refreshToken
              ),
              identifiers,
              expiresIn,
              dpopNonce
            )
          )
        case .failure(let error, let errorDescription):
          throw CredentialIssuanceError.pushedAuthorizationRequestFailed(
            error: error,
            errorDescription: errorDescription
          )
        }
      } catch {
        if let postError = error as? PostError {
          switch postError {
          case .useDpopNonce(let nonce):
            if retry {
              return try await requestAccessTokenPreAuthFlow(
                preAuthorizedCode: preAuthorizedCode,
                txCode: txCode,
                client: client,
                transactionCode: transactionCode,
                identifiers: identifiers,
                dpopNonce: nonce,
                retry: false)
            } else {
              return .failure(ValidationError.retryFailedAfterDpopNonce)
            }
          default:
            return .failure(error)
          }
        } else {
          return .failure(error)
        }
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
      
      return .init(
        type: .init(
          type: OPENID_CREDENTIAL
        ),
        locations: locations,
        credentialConfigurationId: id.value
      )
    }
  }
}

private extension AuthorizationServerClient {
  
  func clientAttestationHeaders(
    clientAttestation: (ClientAttestationJWT, ClientAttestationPoPJWT)?
  ) -> [String: String] {
    guard let clientAttestation = clientAttestation else {
      return [:]
    }
    
    return [
      Constants.OAUTH_CLIENT_ATTESTATION: clientAttestation.0.jws.compactSerializedString,
      Constants.OAUTH_CLIENT_ATTESTATION_POP: clientAttestation.1.jws.compactSerializedString
    ]
  }
  
  func generateClientAttestationIfNeeded(
    clock: ClockType,
    authServerId: URL?
  ) throws -> (ClientAttestationJWT, ClientAttestationPoPJWT)? {
    switch client {
    case .public:
      return nil
    case .attested(let attestationJWT, _):
      guard let clientAttestationPoPBuilder = config.clientAttestationPoPBuilder else {
        return nil
      }
      
      guard let authServerId = authServerId else {
        return nil
      }
      let popJWT = try clientAttestationPoPBuilder.buildAttestationPoPJWT(
        for: client,
        clock: clock,
        authServerId: authServerId
      )
      return (attestationJWT, popJWT)
    }
  }
  
  func tokenEndPointHeaders(
    url: URL?,
    dpopNonce: Nonce? = nil
  ) async throws -> [String: String] {
    if let dpopConstructor, let url {
      let jwt = try await dpopConstructor.jwt(
        endpoint: url,
        accessToken: nil,
        nonce: dpopNonce
      )
      return [Constants.DPOP: jwt]
      
    } else {
      return [:]
    }
  }
  
  func authCodeFlow(
    authorizationCode: String,
    redirectionURI: URL,
    clientId: String,
    codeVerifier: String,
    identifiers: [CredentialConfigurationIdentifier]
  ) -> JSON {
    
    var params: [String: String?] = [
      Constants.GRANT_TYPE_PARAM: Self.grantAuthorizationCode,
      Constants.AUTHORIZATION_CODE_PARAM: authorizationCode,
      Constants.REDIRECT_URI_PARAM: redirectionURI.absoluteString,
      Constants.CLIENT_ID_PARAM: clientId,
      Constants.CODE_VERIFIER_PARAM: codeVerifier
    ]
    
    appendAuthorizationDetailsIfValid(
      to: &params,
      identifiers: identifiers,
      type: .init(type: OPENID_CREDENTIAL)
    )
    
    return JSON(params.filter { $0.value != nil })
  }
  
  func preAuthCodeFlow(
    preAuthorizedCode: String,
    txCode: TxCode?,
    client: Client,
    transactionCode: String?,
    identifiers: [CredentialConfigurationIdentifier]
  ) async throws -> JSON {
    var params: [String: String?] = [
      Constants.CLIENT_ID_PARAM: client.id,
      Constants.GRANT_TYPE_PARAM: Constants.GRANT_TYPE_PARAM_VALUE,
      Constants.PRE_AUTHORIZED_CODE_PARAM: preAuthorizedCode
    ]
    
    if txCode != nil {
      params[Constants.TX_CODE_PARAM] = transactionCode
    }
    
    appendAuthorizationDetailsIfValid(
      to: &params,
      identifiers: identifiers,
      type: .init(type: OPENID_CREDENTIAL)
    )
    
    return JSON(params.filter { $0.value != nil })
  }
  
  func appendAuthorizationDetailsIfValid(
    to params: inout [String: String?],
    identifiers: [CredentialConfigurationIdentifier],
    type: AuthorizationType
  ) {
    
    guard !identifiers.isEmpty else { return }
    
    let formParameterString = identifiers
      .convertToAuthorizationDetails(withType: type)
      .toFormParameterString()
    
    if let formParameterString = formParameterString, !formParameterString.isEmpty {
      params[Constants.AUTHORIZATION_DETAILS] = formParameterString
    }
  }
}

extension Array where Element == CredentialConfigurationIdentifier {
  func convertToAuthorizationDetails(withType type: AuthorizationType) -> [AuthorizationDetail] {
    return self.map { identifier in
      AuthorizationDetail(
        type: type,
        locations: [],
        credentialConfigurationId: identifier.value
      )
    }
  }
}

extension Array where Element == AuthorizationDetail {
  func toFormParameterString() -> String? {
    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys
    
    do {
      let jsonData = try encoder.encode(self)
      if let jsonString = String(data: jsonData, encoding: .utf8) {
        // URL encode the JSON string
        if let urlEncoded = jsonString.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) {
          return urlEncoded
        }
      }
    } catch {}
    return nil
  }
}
