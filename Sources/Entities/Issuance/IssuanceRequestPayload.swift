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

/// Enum representing different types of issuance request payloads.
public enum IssuanceRequestPayload {
  
  /// Payload type for requests based on credential identifiers.
  ///
  /// - Parameters:
  ///   - credentialConfigurationIdentifier: The credential configuration identifier.
  ///   - credentialIdentifier: The credential identifier.
  case identifierBased(
    credentialConfigurationIdentifier: CredentialConfigurationIdentifier,
    credentialIdentifier: CredentialIdentifier
  )
  
  /// Payload type for requests based on credential configurations.
  ///
  /// - Parameters:
  ///   - credentialConfigurationIdentifier: The credential configuration identifier.
  ///   - claimSet: Optional parameter specifying the specific set of claims requested to be included in the credential to be issued.
  case configurationBased(
    credentialConfigurationIdentifier: CredentialConfigurationIdentifier,
    claimSet: ClaimSet?
  )
  
  var credentialConfigurationIdentifier: CredentialConfigurationIdentifier {
    switch self {
    case .identifierBased(let credentialConfigurationIdentifier, _):
      return credentialConfigurationIdentifier
    case .configurationBased(let credentialConfigurationIdentifier, _):
      return credentialConfigurationIdentifier
    }
  }
  
  var claimSet: ClaimSet? {
    switch self {
    case .identifierBased:
      return nil
    case .configurationBased(_, let claimSet):
      return claimSet
    }
  }
}
