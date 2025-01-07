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
    if let nonceValue = headers[Constants.DPOP_NONCE_HEADER] as? String {
      return Nonce(value: nonceValue)
    }
    return nil
  }
}

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
    resource: String?,
    dpopNonce: Nonce?,
    retry: Bool
  ) async throws -> Result<(PKCEVerifier, GetAuthorizationCodeURL, Nonce?), Error>
  
  func requestAccessTokenAuthFlow(
    authorizationCode: String,
    codeVerifier: String,
    identifiers: [CredentialConfigurationIdentifier],
    dpopNonce: Nonce?,
    retry: Bool
  ) async throws -> Result<(
    IssuanceAccessToken,
    CNonce?,
    AuthorizationDetailsIdentifiers?,
    TokenType?,
    Int?,
    Nonce?
  ), Error>
  
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
    CNonce?,
    AuthorizationDetailsIdentifiers?,
    Int?,
    Nonce?), Error>
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
    resource: String? = nil,
    dpopNonce: Nonce? = nil,
    retry: Bool = true
  ) async throws -> Result<(PKCEVerifier, GetAuthorizationCodeURL, Nonce?), Error> {
    guard !scopes.isEmpty else {
      throw ValidationError.error(reason: "No scopes provided. Cannot submit par with no scopes.")
    }
    
    let codeVerifier = PKCEGenerator.codeVerifier() ?? ""
    let authRequest = AuthorizationRequest(
      responseType: Self.responseType,
      clientId: config.client.id,
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

      let clientAttestationHeaders = clientAttestationHeaders(
        clientAttestation: try generateClientAttestationIfNeeded(
          clock: Clock(),
          authServerId: URL(string: authorizationServerMetadata.issuer ?? "")
        )
      )
      
      let tokenHeaders = try await tokenEndPointHeaders(
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
          GetAuthorizationCodeURL.PARAM_CLIENT_ID: config.client.id,
          GetAuthorizationCodeURL.PARAM_REQUEST_STATE: state,
          GetAuthorizationCodeURL.PARAM_REQUEST_URI: requestURI
        ]
        
        guard let urlWithParams = authorizationEndpoint.appendingQueryParameters(queryParams) else {
          throw ValidationError.invalidUrl(parEndpoint.absoluteString)
        }
        
        let authorizationCodeURL = try GetAuthorizationCodeURL(
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
    CNonce?,
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
          authServerId: URL(string: authorizationServerMetadata.issuer ?? "")
        )
      )
      
      let tokenHeaders = try await tokenEndPointHeaders(
        dpopNonce: dpopNonce
      )
      
      let response: ResponseWithHeaders<AccessTokenRequestResponse> = try await service.formPost(
        poster: tokenPoster,
        url: tokenEndpoint,
        headers: clientAttestationHeaders + tokenHeaders,
        parameters: parameters.toDictionary().convertToDictionaryOfStrings()
      )
      
      switch response.body {
      case .success(let tokenType, let accessToken, _, let expiresIn, _, let nonce, _, let identifiers):
        return .success(
          (
            try .init(
              accessToken: accessToken,
              tokenType: .init(
                value: tokenType
              )
            ),
            .init(
              value: nonce
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
    CNonce?,
    AuthorizationDetailsIdentifiers?,
    Int?,
    Nonce?), Error> {
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
          authServerId: URL(string: authorizationServerMetadata.issuer ?? "")
        )
      )
      
      let tokenHeaders = try await tokenEndPointHeaders(
        dpopNonce: dpopNonce
      )
      
      let response: ResponseWithHeaders<AccessTokenRequestResponse> = try await service.formPost(
        poster: tokenPoster,
        url: tokenEndpoint,
        headers: clientAttestationHeaders + tokenHeaders,
        parameters: parameters.toDictionary().convertToDictionaryOfStrings()
      )
      
      switch response.body {
      case .success(let tokenType, let accessToken, _, let expiresIn, _, let nonce, _, let identifiers):
        return .success(
          (
            try .init(
              accessToken: accessToken,
              tokenType: .init(
                value: tokenType
              )
            ),
            .init(
              value: nonce
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
      
      return AuthorizationDetail(
        type: .init(type: OPENID_CREDENTIAL),
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
      "OAuth-Client-Attestation": clientAttestation.0.jws.compactSerializedString,
      "OAuth-Client-Attestation-PoP": clientAttestation.1.jws.compactSerializedString
    ]
  }
  
  func generateClientAttestationIfNeeded(
    clock: ClockType,
    authServerId: URL?
  ) throws -> (ClientAttestationJWT, ClientAttestationPoPJWT)? {
    guard let authServerId = authServerId else {
      throw ValidationError.error(reason: "authServerId missing for client attestation")
    }
    switch client {
    case .public:
      return nil
    case .attested(let attestationJWT, _):
      let popJWT = try config.clientAttestationPoPBuilder.buildAttestationPoPJWT(
        for: client,
        clock: clock,
        authServerId: authServerId
      )
      return (attestationJWT, popJWT)
    }
  }
  
  func tokenEndPointHeaders(dpopNonce: Nonce? = nil) async throws -> [String: String] {
    if let dpopConstructor {
      let jwt = try await dpopConstructor.jwt(
        endpoint: tokenEndpoint,
        accessToken: nil,
        nonce: dpopNonce
      )
      return ["DPoP": jwt]
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
      Constants.CODE_VERIFIER_PARAM: codeVerifier,
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
  ) async throws -> JSON  {
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
