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

public struct GenericErrorResponse: Codable {
  public let error: String
  public let errorDescription: String?
  public let cNonce: String?
  public let cNonceExpiresInSeconds: Int?
  public let interval: Int?
  
  private enum CodingKeys: String, CodingKey {
    case error
    case errorDescription = "error_description"
    case cNonce = "c_nonce"
    case cNonceExpiresInSeconds = "c_nonce_expires_in"
    case interval
  }
  
  public init(
    error: String,
    errorDescription: String?,
    cNonce: String?,
    cNonceExpiresInSeconds: Int?,
    interval: Int?
  ) {
    self.error = error
    self.errorDescription = errorDescription
    self.cNonce = cNonce
    self.cNonceExpiresInSeconds = cNonceExpiresInSeconds
    self.interval = interval
  }
}

public extension GenericErrorResponse {
  
  func toIssuanceError() -> CredentialIssuanceError {
    switch error {
    case "invalid_proof":
      if let cNonce {
        return .invalidProof(
          cNonce: cNonce,
          cNonceExpiresIn: cNonceExpiresInSeconds,
          errorDescription: errorDescription
        )
        
      } else {
        return .responseUnparsable("Issuer responded with invalid_proof error but no c_nonce was provided")
      }
    case "issuance_pending":
      return .deferredCredentialIssuancePending(interval: interval)
    case "invalid_token": return .invalidToken
    case "invalid_transaction_id": return .invalidTransactionId
    case "unsupported_credential_type":
      return .unsupportedCredentialType
    case "unsupported_credential_format": return .unsupportedCredentialFormat
    case "invalid_encryption_parameters": return .invalidEncryptionParameters
    default: return .issuanceRequestFailed(
      error: error,
      errorDescription: errorDescription
    )
    }
  }
}
