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

/// State denoting that the pushed authorization request has been placed successfully and response processed
public struct AuthorizationRequested: Sendable {
  public let credentials: [CredentialIdentifier]
  public let authorizationCodeURL: AuthorizationCodeURL
  public let pkceVerifier: PKCEVerifier
  public let state: String
  public let configurationIds: [CredentialConfigurationIdentifier]
  public let dpopNonce: Nonce?
  /// The authorization server's `issuer` value at the time the request was prepared. Used to
  /// bind the authorization response's RFC 9207 `iss` parameter to a single, trusted AS at
  /// callback time.
  public let expectedIssuer: URL?
  /// True when the authorization server metadata declares
  /// `authorization_response_iss_parameter_supported: true`. If so, the wallet MUST receive an
  /// `iss` parameter in the authorization response per RFC 9207.
  public let issParameterRequired: Bool

  public init(
    credentials: [CredentialIdentifier],
    authorizationCodeURL: AuthorizationCodeURL,
    pkceVerifier: PKCEVerifier,
    state: String,
    configurationIds: [CredentialConfigurationIdentifier],
    dpopNonce: Nonce? = nil,
    expectedIssuer: URL? = nil,
    issParameterRequired: Bool = false
  ) {
    self.credentials = credentials
    self.authorizationCodeURL = authorizationCodeURL
    self.pkceVerifier = pkceVerifier
    self.state = state
    self.configurationIds = configurationIds
    self.dpopNonce = dpopNonce
    self.expectedIssuer = expectedIssuer
    self.issParameterRequired = issParameterRequired
  }
}
