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

public struct IssuanceRefreshToken: Codable, CanExpire, Sendable {
  public var expiresIn: TimeInterval?
    
  public let refreshToken: String?

  /// Lifetime of the authorization behind this refresh token, in seconds from when the token
  /// response was received (`authorization_expires_in`), or `nil` when the server didn't send it.
  public let authorizationExpiresIn: TimeInterval?

  public init(
    refreshToken: String?,
    expiresIn: TimeInterval? = nil,
    authorizationExpiresIn: TimeInterval? = nil
  ) throws {
    self.refreshToken = refreshToken
    self.expiresIn = expiresIn
    self.authorizationExpiresIn = authorizationExpiresIn
  }
}
