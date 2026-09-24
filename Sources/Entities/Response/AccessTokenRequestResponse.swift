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

public enum AccessTokenRequestResponse: Codable, Sendable {
  case success(
    tokenType: String?,
    accessToken: String,
    refreshToken: String?,
    refreshTokenExpiresIn: Int?,
    expiresIn: Int,
    scope: String?,
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
    case refreshTokenExpiresIn = "refresh_expires_in"
    case expiresIn = "expires_in"
    case scope
    case error
    case errorDescription = "error_description"
    case authorizationDetails = "authorization_details"
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)

    if let accessToken = try? container.decode(String.self, forKey: .accessToken) {
      // RFC 6749 §4.2.2: `expires_in` is OPTIONAL and RECOMMENDED as an integer, but many
      // authorization servers serialize it as a JSON string. Accept either, and default to 0
      // when the field is absent so that a legitimate token response with no `expires_in`
      // does not fall through to the failure branch and end up in a `cannotParse` error whose
      // raw body would leak access / refresh tokens.
      let expiresIn = Self.lenientNumber(from: container, forKey: .expiresIn) ?? 0

      let tokenType = try? container.decode(String.self, forKey: .tokenType)
      let refeshToken = try? container.decode(String.self, forKey: .refreshToken)
      let refreshTokenExpiresIn = Self.lenientNumber(from: container, forKey: .refreshTokenExpiresIn)
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
        refreshTokenExpiresIn: refreshTokenExpiresIn,
        expiresIn: expiresIn,
        scope: try? container.decode(String.self, forKey: .scope),
        authorizationDetails: (authorizationDetails.isEmpty ? nil : authorizationDetails)
      )
    } else if let error = try? container.decode(String.self, forKey: .error) {
      // RFC 6749 §5.2: `error_description` is OPTIONAL; treat a valid error response with
      // no description as failure rather than falling through.
      let errorDescription = try? container.decode(String.self, forKey: .errorDescription)
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
  
  /// Decode an integer from a container even when the wire representation is a JSON string.
  /// Returns nil only when the key is truly absent or the value is neither number nor
  /// integer-shaped string.
  private static func lenientNumber(
    from container: KeyedDecodingContainer<CodingKeys>,
    forKey key: CodingKeys
  ) -> Int? {
    if let n = try? container.decode(Int.self, forKey: key) { return n }
    if let s = try? container.decode(String.self, forKey: key), let n = Int(s) { return n }
    return nil
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    
    switch self {
    case let .success(
      tokenType,
      accessToken,
      refreshToken,
      refreshTokenExpiresIn,
      expiresIn,
      scope,
      _
    ):
      try container.encode(tokenType, forKey: .tokenType)
      try container.encode(accessToken, forKey: .accessToken)
      try container.encode(refreshToken, forKey: .refreshToken)
      try container.encode(refreshTokenExpiresIn, forKey: .refreshTokenExpiresIn)
      try container.encode(expiresIn, forKey: .expiresIn)
      try container.encode(scope, forKey: .scope)
    case let .failure(error, errorDescription):
      try container.encode(error, forKey: .error)
      try container.encode(errorDescription, forKey: .errorDescription)
    }
  }
}
