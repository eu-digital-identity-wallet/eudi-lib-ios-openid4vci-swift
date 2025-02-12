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

public enum AuthorizeIssuanceConfig {
  case favorScopes
  case authorizationDetails
}

public typealias ClientId = String
public typealias ClientSecret = String

public struct OpenId4VCIConfig {
  public let client: Client
  public let authFlowRedirectionURI: URL
  public let authorizeIssuanceConfig: AuthorizeIssuanceConfig
  public let usePAR: Bool
  public let dPoPConstructor: DPoPConstructorType?
  public let clientAttestationPoPBuilder: ClientAttestationPoPBuilder?

    
  public init(
    client: Client,
    authFlowRedirectionURI: URL,
    authorizeIssuanceConfig: AuthorizeIssuanceConfig = .favorScopes,
    usePAR: Bool = true,
    dPoPConstructor: DPoPConstructorType? = nil,
    clientAttestationPoPBuilder: ClientAttestationPoPBuilder? = nil
  ) {
    self.client = client
    self.authFlowRedirectionURI = authFlowRedirectionURI
    self.authorizeIssuanceConfig = authorizeIssuanceConfig
    self.usePAR = usePAR
    self.dPoPConstructor = dPoPConstructor
    self.clientAttestationPoPBuilder = clientAttestationPoPBuilder
  }
}

