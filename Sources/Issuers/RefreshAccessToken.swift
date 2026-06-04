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

/// A protocol that defines the capability to refresh an access token.
///
public protocol RefreshAccessToken: Sendable {

  /// Refreshes the access token in an authorized request.
  ///
  /// This method attempts to refresh the access token using the refresh token
  /// present in the provided `AuthorizedRequest`. If the request does not contain
  /// a refresh token, or if the refresh token has expired, the original request
  /// is returned unchanged.
  ///
  /// The client credentials are obtained from the issuer's configuration, so they
  /// do not need to be provided separately.
  ///
  /// - Parameters:
  ///   - authorizedRequest: The authorized request containing the tokens to refresh.
  ///   - dPopNonce: An optional nonce for DPoP (Demonstrating Proof-of-Possession).
  /// - Returns: A new `AuthorizedRequest` with refreshed tokens if successful,
  ///            or the original request if refresh is not possible.
  /// - Throws: An error if the token refresh request fails.
  func refresh(
    authorizedRequest: AuthorizedRequest,
    dPopNonce: Nonce?
  ) async throws -> AuthorizedRequest
}

public extension RefreshAccessToken {

  /// Refreshes the access token in an authorized request with default DPoP nonce.
  ///
  /// This convenience method calls the main refresh method with a nil DPoP nonce.
  ///
  /// - Parameter authorizedRequest: The authorized request containing the tokens to refresh.
  /// - Returns: A new `AuthorizedRequest` with refreshed tokens if successful,
  ///            or the original request if refresh is not possible.
  /// - Throws: An error if the token refresh request fails.
  func refresh(
    authorizedRequest: AuthorizedRequest
  ) async throws -> AuthorizedRequest {
    try await refresh(authorizedRequest: authorizedRequest, dPopNonce: nil)
  }
}
