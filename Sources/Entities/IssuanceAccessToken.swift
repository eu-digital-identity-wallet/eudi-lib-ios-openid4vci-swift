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

public enum TokenType: String, Codable {
  case bearer = "Bearer"
  case dpop = "DPoP"
  
  public init(value: String?) {
    guard let value else {
      self = .bearer
      return
    }
    
    if value == TokenType.bearer.rawValue {
      self = .bearer
    } else if value == TokenType.dpop.rawValue {
      self = .dpop
    } else {
      self = .bearer
    }
  }
}

public struct IssuanceAccessToken: Codable, CanExpire {
  public var expiresIn: TimeInterval?
    
  public let accessToken: String
  public let tokenType: TokenType?
  
  public init(
    accessToken: String,
    tokenType: TokenType?,
    expiresIn: TimeInterval = .zero
  ) throws {
    guard !accessToken.isEmpty else {
      throw ValidationError.error(reason: "Access token cannot be empty")
    }
    self.accessToken = accessToken
    self.tokenType = tokenType
    self.expiresIn = expiresIn
  }
}

public extension IssuanceAccessToken {
  var authorizationHeader: [String: String] {
    ["Authorization": "\(TokenType.bearer.rawValue) \(accessToken)"]
  }
  
  func dPoPOrBearerAuthorizationHeader(
    dpopConstructor: DPoPConstructorType?,
    endpoint: URL?
  ) async throws -> [String: String] {
    if tokenType == TokenType.bearer {
      return ["Authorization": "\(TokenType.bearer.rawValue) \(accessToken)"]
    } else if let dpopConstructor, tokenType == TokenType.dpop, let endpoint {
      let jwt = try await dpopConstructor.jwt(endpoint: endpoint, accessToken: accessToken)
      return [
        "Authorization": "\(TokenType.dpop.rawValue) \(accessToken)",
        TokenType.dpop.rawValue: jwt
      ]
    }
    return ["Authorization": "\(TokenType.bearer.rawValue) \(accessToken)"]
  }
}
