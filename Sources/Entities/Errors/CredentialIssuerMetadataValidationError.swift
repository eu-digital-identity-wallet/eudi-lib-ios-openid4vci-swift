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

public enum CredentialIssuerMetadataValidationError: Error {
  case invalidCredentialIssuerId(reason: String)
  case invalidAuthorizationServer(reason: String)
  case invalidCredentialEndpoint(reason: String)
  case invalidBatchCredentialEndpoint(reason: String)
  case invalidDeferredCredentialEndpoint(reason: String)
  case invalidCredentialResponseEncryptionAlgorithmsSupported(reason: String)
  case invalidCredentialResponseEncryptionMethodsSupported(reason: String)
  case credentialResponseEncryptionAlgorithmsRequired
  case invalidCredentialsSupported(reason: String)
  case credentialsSupportedRequired
  case invalidDisplay(reason: String)
}
