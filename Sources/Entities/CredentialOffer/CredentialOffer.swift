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

public struct CredentialOffer: Sendable {
  public let credentialIssuerIdentifier: CredentialIssuerId
  public let credentialIssuerMetadata: CredentialIssuerMetadata
  public let credentialConfigurationIdentifiers: [CredentialConfigurationIdentifier]
  public let grants: Grants?

  //// Authorization server metadata for the authorization code flow.
  public let authorizationCodeServerMetadata: IdentityAndAccessManagementMetadata?

  //// Authorization server metadata for the pre-authorization code flow.
  //// When different from authorizationCodeServerMetadata, the pre-auth flow
  //// will use this server's token endpoint.
  public let preAuthorizationCodeServerMetadata: IdentityAndAccessManagementMetadata?

  //// Primary authorization server metadata, guaranteed to be non-nil.
  //// This is set during initialization to whichever metadata is available,
  //// preferring the authorization code server.
  private let primaryAuthorizationServerMetadata: IdentityAndAccessManagementMetadata

  //// Returns the authorization server metadata, preferring the authorization code server.
  //// This property maintains backward compatibility with code that expects a single metadata.
  public var authorizationServerMetadata: IdentityAndAccessManagementMetadata {
    primaryAuthorizationServerMetadata
  }

  public init(
    credentialIssuerIdentifier: CredentialIssuerId,
    credentialIssuerMetadata: CredentialIssuerMetadata,
    credentialConfigurationIdentifiers: [CredentialConfigurationIdentifier],
    grants: Grants? = nil,
    authorizationCodeServerMetadata: IdentityAndAccessManagementMetadata?,
    preAuthorizationCodeServerMetadata: IdentityAndAccessManagementMetadata?
  ) throws {
    self.credentialIssuerIdentifier = credentialIssuerIdentifier
    self.credentialIssuerMetadata = credentialIssuerMetadata
    self.credentialConfigurationIdentifiers = credentialConfigurationIdentifiers
    self.grants = grants
    self.authorizationCodeServerMetadata = authorizationCodeServerMetadata
    self.preAuthorizationCodeServerMetadata = preAuthorizationCodeServerMetadata

    // At least one authorization server metadata must be provided
    guard let primary = authorizationCodeServerMetadata ?? preAuthorizationCodeServerMetadata else {
      throw ValidationError.error(reason: "At least one authorization server metadata must be provided")
    }
    self.primaryAuthorizationServerMetadata = primary

    if credentialConfigurationIdentifiers.isEmpty {
      throw CredentialOfferRequestError.emptyCredentialsError
    }
  }

  /// Convenience initializer for backward compatibility when a single authorization server is used.
  public init(
    credentialIssuerIdentifier: CredentialIssuerId,
    credentialIssuerMetadata: CredentialIssuerMetadata,
    credentialConfigurationIdentifiers: [CredentialConfigurationIdentifier],
    grants: Grants? = nil,
    authorizationServerMetadata: IdentityAndAccessManagementMetadata
  ) throws {
    try self.init(
      credentialIssuerIdentifier: credentialIssuerIdentifier,
      credentialIssuerMetadata: credentialIssuerMetadata,
      credentialConfigurationIdentifiers: credentialConfigurationIdentifiers,
      grants: grants,
      authorizationCodeServerMetadata: authorizationServerMetadata,
      preAuthorizationCodeServerMetadata: authorizationServerMetadata
    )
  }
}
