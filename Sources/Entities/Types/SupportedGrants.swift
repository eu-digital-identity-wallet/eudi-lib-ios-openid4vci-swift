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

/// Wallet-supported grant types.
public enum SupportedGrants: Sendable, Equatable {
  /// Wallet supports Authorization Code grant.
  case authorizationCode
  /// Wallet supports Pre-authorized Code grant.
  case preAuthorizedCode
  /// Wallet supports both Authorization Code and Pre-authorized Code grants.
  case both

  /// Checks if the wallet supports the given grants from a credential offer.
  /// - Parameter grants: The grants from a credential offer.
  /// - Returns: `true` if the wallet supports the grants, `false` otherwise.
  public func supports(_ grants: Grants) -> Bool {
    switch (self, grants) {
    case (.authorizationCode, .authorizationCode):
      return true
    case (.preAuthorizedCode, .preAuthorizedCode):
      return true
    case (.both, _):
      return true
    case (.authorizationCode, .both):
      return true
    case (.preAuthorizedCode, .both):
      return true
    default:
      return false
    }
  }

  /// Returns whether this configuration requires authorization code flow support.
  public var requiresAuthorizationCodeFlow: Bool {
    switch self {
    case .authorizationCode, .both:
      return true
    case .preAuthorizedCode:
      return false
    }
  }
}
