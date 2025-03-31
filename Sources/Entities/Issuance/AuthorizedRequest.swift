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

public protocol CanExpire: Sendable {
  var expiresIn: TimeInterval? { get }
  func isExpired(issued: TimeInterval, at: TimeInterval) -> Bool
}

public extension CanExpire {
  func isExpired(issued: TimeInterval, at: TimeInterval) -> Bool {
    if issued >= at {
      return true
    }
    
    guard let expiresIn = expiresIn else {
      return false
    }
    
    let expiration = issued + expiresIn
    return expiration >= at
  }
}

public struct AuthorizedRequest: Sendable {
  public let accessToken: IssuanceAccessToken
  public let refreshToken: IssuanceRefreshToken?
  public let credentialIdentifiers: AuthorizationDetailsIdentifiers?
  public let timeStamp: TimeInterval
  public let dPopNonce: Nonce?
  
  public init(
    accessToken: IssuanceAccessToken,
    refreshToken: IssuanceRefreshToken?,
    credentialIdentifiers: AuthorizationDetailsIdentifiers?,
    timeStamp: TimeInterval,
    dPopNonce: Nonce?
  ) {
    self.accessToken = accessToken
    self.refreshToken = refreshToken
    self.credentialIdentifiers = credentialIdentifiers
    self.timeStamp = timeStamp
    self.dPopNonce = dPopNonce
  }
  
  public func isAccessTokenExpired(
    _ from: TimeInterval = Date().timeIntervalSince1970
  ) -> Bool {
    return accessToken.isExpired(issued: timeStamp, at: from)
  }
  
  public func isRefreshTokenExpired(clock: TimeInterval) -> Bool {
    return accessToken.isExpired(
      issued: timeStamp,
      at: clock
    )
  }
}

extension AuthorizedRequest {
  /// Returns a copy of the current `AuthorizedRequest`, replacing the `accessToken` and `timeStamp`
  /// - Parameters:
  ///   - newAccessToken: The new `IssuanceAccessToken` to use.
  ///   - newTimeStamp: The new `TimeInterval` to use.
  /// - Returns: A new `AuthorizedRequest` instance with the updated values.
  func replacing(accessToken newAccessToken: IssuanceAccessToken, timeStamp newTimeStamp: TimeInterval) -> AuthorizedRequest {
    return .init(
      accessToken: newAccessToken,
      refreshToken: refreshToken,
      credentialIdentifiers: credentialIdentifiers,
      timeStamp: newTimeStamp,
      dPopNonce: dPopNonce
    )
  }
}

