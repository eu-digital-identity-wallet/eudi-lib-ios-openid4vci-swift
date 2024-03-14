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

/// An enumeration representing errors that can occur during validation of credential issuer metadata.
public enum CredentialIssuerMetadataValidationError: Error {
  /// The credential issuer ID is invalid.
  /// - Parameter reason: The reason for the invalidity.
  case invalidCredentialIssuerId(reason: String)
  
  /// The authorization server is invalid.
  /// - Parameter reason: The reason for the invalidity.
  case invalidAuthorizationServer(reason: String)
  
  /// The credential endpoint is invalid.
  /// - Parameter reason: The reason for the invalidity.
  case invalidCredentialEndpoint(reason: String)
  
  /// The batch credential endpoint is invalid.
  /// - Parameter reason: The reason for the invalidity.
  case invalidBatchCredentialEndpoint(reason: String)
  
  /// The deferred credential endpoint is invalid.
  /// - Parameter reason: The reason for the invalidity.
  case invalidDeferredCredentialEndpoint(reason: String)
  
  /// The credential response encryption algorithms supported are invalid.
  /// - Parameter reason: The reason for the invalidity.
  case invalidCredentialResponseEncryptionAlgorithmsSupported(reason: String)
  
  /// The credential response encryption methods supported are invalid.
  /// - Parameter reason: The reason for the invalidity.
  case invalidCredentialResponseEncryptionMethodsSupported(reason: String)
  
  /// The required credential response encryption algorithms are invalid.
  case credentialResponseEncryptionAlgorithmsRequired
  
  /// The credentials supported are invalid.
  /// - Parameter reason: The reason for the invalidity.
  case invalidCredentialsSupported(reason: String)
  
  /// The required credentials supported are invalid.
  case credentialsSupportedRequired
  
  /// The display value is invalid.
  /// - Parameter reason: The reason for the invalidity.
  case invalidDisplay(reason: String)
  
  /// The URL of the Notification Endpoint is  invalid.
  case invalidNotificationEndpoint
}
