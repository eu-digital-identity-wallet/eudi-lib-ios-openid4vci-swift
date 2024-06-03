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

public struct AuthorizationRequest: Codable {
  public let responseType: String?
  public let clientId: String?
  public let redirectUri: String?
  public let scope: String?
  public let credentialConfigurationIds: [AuthorizationDetail]?
  public let state: String?
  public let responseMode: String?
  public let codeChallenge: String?
  public let codeChallengeMethod: String?
  public let authorizationDetails: String?
  public let resource: String?
  public let includeGrantedScopes: String?
  public let requestUri: String?
  public let request: String?
  public let prompt: String?
  public let dpopJkt: String?
  public let trustChain: String?
  
  public let issuerState: String?
  
  enum CodingKeys: String, CodingKey {
    case responseType = "response_type"
    case clientId = "client_id"
    case redirectUri = "redirect_uri"
    case scope
    case credentialConfigurationIds = "credential_configuration_ids"
    case state
    case responseMode = "response_mode"
    case codeChallenge = "code_challenge"
    case codeChallengeMethod = "code_challenge_method"
    case authorizationDetails = "authorization_details"
    case resource
    case includeGrantedScopes = "include_granted_scopes"
    case requestUri = "request_uri"
    case request
    case prompt
    case dpopJkt = "dpop_jkt"
    case trustChain = "trust_chain"
    
    case issuerState = "issuer_state"
  }
  
  public init(
    responseType: String? = nil,
    clientId: String? = nil,
    redirectUri: String? = nil,
    scope: String? = nil,
    credentialConfigurationIds: [AuthorizationDetail]? = nil,
    state: String? = nil,
    responseMode: String? = nil,
    codeChallenge: String? = nil,
    codeChallengeMethod: String? = nil,
    authorizationDetails: String? = nil,
    resource: String? = nil,
    includeGrantedScopes: String? = nil,
    requestUri: String? = nil,
    request: String? = nil,
    prompt: String? = nil,
    dpopJkt: String? = nil,
    trustChain: String? = nil,
    issuerState: String? = nil
  ) {
    self.responseType = responseType
    self.clientId = clientId
    self.redirectUri = redirectUri
    self.scope = scope
    self.credentialConfigurationIds = credentialConfigurationIds
    self.state = state
    self.responseMode = responseMode
    self.codeChallenge = codeChallenge
    self.codeChallengeMethod = codeChallengeMethod
    self.authorizationDetails = authorizationDetails
    self.resource = resource
    self.includeGrantedScopes = includeGrantedScopes
    self.requestUri = requestUri
    self.request = request
    self.prompt = prompt
    self.dpopJkt = dpopJkt
    self.trustChain = trustChain
    
    self.issuerState = issuerState
  }
}

