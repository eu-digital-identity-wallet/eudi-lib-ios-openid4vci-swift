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

public struct CredentialOffer {
  public let credentialIssuerIdentifier: CredentialIssuerId
  public let credentialIssuerMetadata: CredentialIssuerMetadata
  public let credentialConfigurationIdentifiers: [CredentialConfigurationIdentifier]
  public let grants: Grants?
  public let authorizationServerMetadata: IdentityAndAccessManagementMetadata
  
  public init(
    credentialIssuerIdentifier: CredentialIssuerId,
    credentialIssuerMetadata: CredentialIssuerMetadata,
    credentialConfigurationIdentifiers: [CredentialConfigurationIdentifier],
    grants: Grants? = nil,
    authorizationServerMetadata: IdentityAndAccessManagementMetadata
  ) throws {
    self.credentialIssuerIdentifier = credentialIssuerIdentifier
    self.credentialIssuerMetadata = credentialIssuerMetadata
    self.credentialConfigurationIdentifiers = credentialConfigurationIdentifiers
    self.grants = grants
    self.authorizationServerMetadata = authorizationServerMetadata
    
    if credentialConfigurationIdentifiers.isEmpty {
      throw CredentialOfferRequestError.emptyCredentialsError
    }
  }
}

