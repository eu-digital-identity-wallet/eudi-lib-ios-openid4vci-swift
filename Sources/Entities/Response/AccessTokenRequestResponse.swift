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

public typealias AuthorizationDetailsIdentifiers = [CredentialConfigurationIdentifier: [CredentialIdentifier]]

public enum AccessTokenRequestResponse: Codable {
  case success(
    tokenType: String?,
    accessToken: String,
    refreshToken: String?,
    expiresIn: Int,
    scope: String?,
    cNonce: String?,
    cNonceExpiresIn: Int?,
    authorizationDetails: AuthorizationDetailsIdentifiers?
  )
  case failure(
    error: String,
    errorDescription: String?
  )
  
  enum CodingKeys: String, CodingKey {
    case tokenType = "token_type"
    case accessToken = "access_token"
    case refreshToken = "refresh_token"
    case expiresIn = "expires_in"
    case scope
    case error
    case cNonce = "c_nonce"
    case cNonceExpiresIn = "c_nonce_expires_in"
    case errorDescription = "error_description"
    case authorizationDetails = "authorization_details"
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    
    if let accessToken = try? container.decode(String.self, forKey: .accessToken),
       let expiresIn = try? container.decode(Int.self, forKey: .expiresIn) {
      
      let tokenType = try? container.decode(String.self, forKey: .tokenType)
      let refeshToken = try? container.decode(String.self, forKey: .refreshToken)
      var authorizationDetails: AuthorizationDetailsIdentifiers = [:]
      
      let json = try? container.decode(JSON.self, forKey: .authorizationDetails)
      if let array = json?.array {
        for item in array {
          if let key = item["credential_configuration_id"].string,
             let values = item["credential_identifiers"].array,
             let credentialConfigurationIdentifier = try? CredentialConfigurationIdentifier(value: key) {
            
            let credentialIdentifiers: [CredentialIdentifier] = values.compactMap {
              guard let string = $0.string else { return nil }
              return try? CredentialIdentifier(value: string)
            }
            
            if !credentialIdentifiers.isEmpty {
              authorizationDetails[credentialConfigurationIdentifier] = credentialIdentifiers
            }
          }
        }
      }
      
      self = .success(
        tokenType: tokenType,
        accessToken: accessToken,
        refreshToken: refeshToken,
        expiresIn: expiresIn,
        scope: try? container.decode(String.self, forKey: .scope),
        cNonce: try? container.decode(String.self, forKey: .cNonce),
        cNonceExpiresIn: try? container.decode(Int.self, forKey: .cNonceExpiresIn),
        authorizationDetails: (authorizationDetails.isEmpty ? nil : authorizationDetails)
      )
    } else if let error = try? container.decode(String.self, forKey: .error),
              let errorDescription = try? container.decode(String.self, forKey: .errorDescription) {
      self = .failure(error: error, errorDescription: errorDescription)
    } else {
      throw DecodingError.dataCorrupted(
        DecodingError.Context(
          codingPath: decoder.codingPath,
          debugDescription: "Invalid response format"
        )
      )
    }
  }
  
  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    
    switch self {
    case let .success(
      tokenType,
      accessToken,
      refreshToken,
      expiresIn,
      scope,
      cNonce,
      cNonceExpiresIn,
      _
    ):
      try container.encode(tokenType, forKey: .tokenType)
      try container.encode(accessToken, forKey: .accessToken)
      try container.encode(refreshToken, forKey: .refreshToken)
      try container.encode(expiresIn, forKey: .expiresIn)
      try container.encode(scope, forKey: .scope)
      try container.encode(cNonce, forKey: .cNonce)
      try container.encode(cNonceExpiresIn, forKey: .cNonceExpiresIn)
    case let .failure(error, errorDescription):
      try container.encode(error, forKey: .error)
      try container.encode(errorDescription, forKey: .errorDescription)
    }
  }
}

