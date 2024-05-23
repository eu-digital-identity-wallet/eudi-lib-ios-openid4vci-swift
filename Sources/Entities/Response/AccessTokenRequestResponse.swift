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

public typealias AuthorizationDetailsIdentifiers = [CredentialConfigurationIdentifier: [CredentialIdentifier]]

public enum AccessTokenRequestResponse: Codable {
  case success(
    accessToken: String,
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
    case accessToken = "access_token"
    case expiresIn = "expires_in"
    case scope
    case error
    case cNonce = "c_nonce"
    case cNonceExpiresIn = "c_nonce_expires_in"
    case errorDescription = "error_description"
  }
  
  struct DynamicKey: CodingKey {
    var stringValue: String
    init?(stringValue: String) {
      self.stringValue = stringValue
    }
    
    var intValue: Int? { return nil }
    init?(intValue: Int) { return nil }
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    
    if let accessToken = try? container.decode(String.self, forKey: .accessToken),
       let expiresIn = try? container.decode(Int.self, forKey: .expiresIn) {
      
      var authorizationDetails: AuthorizationDetailsIdentifiers = [:]
      
      // Decode the dynamic key dictionary
      if let dynamicKeyContainer = try? decoder.container(keyedBy: DynamicKey.self) {
        var dynamicKeyDictionary = [CredentialConfigurationIdentifier: [CredentialIdentifier]]()
        for key in dynamicKeyContainer.allKeys {
          if let identifier = try? CredentialConfigurationIdentifier(value: key.stringValue),
             let values = (try? dynamicKeyContainer.decode([String].self, forKey: key))?.compactMap({ try? CredentialIdentifier(value: $0)}) {
            dynamicKeyDictionary[identifier] = values
          }
        }
        authorizationDetails = dynamicKeyDictionary
      }
      
      self = .success(
        accessToken: accessToken,
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
    case let .success(accessToken, expiresIn, scope, cNonce, cNonceExpiresIn, _):
      try container.encode(accessToken, forKey: .accessToken)
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

