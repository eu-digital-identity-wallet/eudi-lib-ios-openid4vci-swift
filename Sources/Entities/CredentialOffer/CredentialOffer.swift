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

/// Holds per-grant authorization server metadata.
/// Each grant type (authorization code, pre-authorization code) can specify
/// a different authorization server, and this struct captures the resolved
/// metadata for each.
public struct GrantsMetadata: Sendable {

  /// Metadata for the authorization code flow.
  public let authorizationCode: IdentityAndAccessManagementMetadata?

  /// Metadata for the pre-authorization code flow.
  /// When different from `authorizationCode`, the pre-auth flow
  /// will use this server's token endpoint.
  public let preAuthorizationCode: IdentityAndAccessManagementMetadata?

  /// Primary metadata, guaranteed to be non-nil.
  /// Prefers authorization code metadata, falls back to pre-authorization code.
  public let primary: IdentityAndAccessManagementMetadata

  /// Creates metadata for both grant types.
  /// At least one metadata must be provided.
  public init(
    authorizationCode: IdentityAndAccessManagementMetadata?,
    preAuthorizationCode: IdentityAndAccessManagementMetadata?
  ) throws {
    guard let primary = authorizationCode ?? preAuthorizationCode else {
      throw ValidationError.error(reason: "At least one authorization server metadata must be provided")
    }
    self.authorizationCode = authorizationCode
    self.preAuthorizationCode = preAuthorizationCode
    self.primary = primary
  }

  /// Convenience initializer when both grants use the same authorization server.
  public init(shared: IdentityAndAccessManagementMetadata) {
    self.authorizationCode = shared
    self.preAuthorizationCode = shared
    self.primary = shared
  }
}

public struct CredentialOffer: Sendable {
  public let credentialIssuerIdentifier: CredentialIssuerId
  public let credentialIssuerMetadata: CredentialIssuerMetadata
  public let credentialConfigurationIdentifiers: [CredentialConfigurationIdentifier]
  public let grants: Grants?

  /// Per-grant authorization server metadata.
  public let grantsMetadata: GrantsMetadata

  /// Returns the primary authorization server metadata.
  /// Maintains backward compatibility with code that expects a single metadata.
  public var authorizationServerMetadata: IdentityAndAccessManagementMetadata {
    grantsMetadata.primary
  }

  public init(
    credentialIssuerIdentifier: CredentialIssuerId,
    credentialIssuerMetadata: CredentialIssuerMetadata,
    credentialConfigurationIdentifiers: [CredentialConfigurationIdentifier],
    grants: Grants? = nil,
    grantsMetadata: GrantsMetadata
  ) throws {
    self.credentialIssuerIdentifier = credentialIssuerIdentifier
    self.credentialIssuerMetadata = credentialIssuerMetadata
    self.credentialConfigurationIdentifiers = credentialConfigurationIdentifiers
    self.grants = grants
    self.grantsMetadata = grantsMetadata

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
      grantsMetadata: GrantsMetadata(shared: authorizationServerMetadata)
    )
  }
}
