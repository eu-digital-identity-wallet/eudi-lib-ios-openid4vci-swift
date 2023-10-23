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

public struct CredentialIssuerMetadata: Codable, Equatable {
  let credentialIssuerIdentifier: String
  let authorizationServer: String?
  let credentialEndpoint: String
  let batchCredentialEndpoint: String?
  let deferredCredentialEndpoint: String?
  let credentialResponseEncryptionAlgorithmsSupported: [String]?
  let credentialResponseEncryptionMethodsSupported: [String]?
  let requireCredentialResponseEncryption: Bool?
  let credentialsSupported: [JSON]
  let display: [Display]?
  
  enum CodingKeys: String, CodingKey {
    case credentialIssuerIdentifier = "credential_issuer"
    case authorizationServer = "authorization_server"
    case credentialEndpoint = "credential_endpoint"
    case batchCredentialEndpoint = "batch_credential_endpoint"
    case deferredCredentialEndpoint = "deferred_credential_endpoint"
    case credentialResponseEncryptionAlgorithmsSupported = "credential_response_encryption_alg_values_supported"
    case credentialResponseEncryptionMethodsSupported = "credential_response_encryption_enc_values_supported"
    case requireCredentialResponseEncryption = "require_credential_response_encryption"
    case credentialsSupported = "credentials_supported"
    case display = "display"
  }
}
