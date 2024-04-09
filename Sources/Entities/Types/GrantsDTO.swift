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

// Grant, conforming to Codable.
public struct GrantsDTO: Codable {
  // Properties for authorization code and pre-authorization code.
  public let authorizationCode: AuthorizationCode?
  public let preAuthorizationCode: PreAuthorizationCode?
  
  // CodingKeys enumeration to map JSON keys to struct properties.
  enum CodingKeys: String, CodingKey {
    case authorizationCode = "authorization_code"
    case preAuthorizationCode = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
  }
  
  public init(
    authorizationCode: AuthorizationCode?,
    preAuthorizationCode: PreAuthorizationCode?
  ) {
    self.authorizationCode = authorizationCode
    self.preAuthorizationCode = preAuthorizationCode
  }
}

// Grant extension
public extension GrantsDTO {
  
  // AuthorizationCode, conforming to Codable.
  struct AuthorizationCode: Codable, Equatable {
    // Property representing issuer state.
    let issuerState: String?
    
    // Property representing authorization url.
    let authorizationServer: String?
    
    // CodingKeys enumeration to map JSON keys to struct properties.
    enum CodingKeys: String, CodingKey {
      case issuerState = "issuer_state"
      case authorizationServer = "authorization_server"
    }
    
    public init(issuerState: String, authorizationServer: String) {
      self.issuerState = issuerState
      self.authorizationServer = authorizationServer
    }
  }
  
  // Define another nested struct named PreAuthorizationCode, conforming to Codable.
  struct PreAuthorizationCode: Codable {
    public let preAuthorizedCode: String?
    public let txCode: TxCode?
    
    enum CodingKeys: String, CodingKey {
      case preAuthorizedCode = "pre-authorized_code"
      case txCode = "tx_code"
    }
    
    public init(preAuthorizedCode: String, txCode: TxCode?) {
      self.preAuthorizedCode = preAuthorizedCode
      self.txCode = txCode
    }
  }
}
