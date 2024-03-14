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

public enum CredentialIssuanceError: Error, LocalizedError {
  case pushedAuthorizationRequestFailed(error: String, errorDescription: String?)
  case accessTokenRequestFailed(error: String, errorDescription: String?)
  case issuerDoesNotSupportBatchIssuance
  case responseUnparsable(String)
  case invalidIssuanceRequest(String)
  case cryptographicSuiteNotSupported(String)
  case cryptographicBindingMethodNotSupported
  case proofTypeNotSupported
  case cryptographicAlgorithmNotSupported
  
  case issuerDoesNotSupportEncryptedResponses
  case responseEncryptionAlgorithmNotSupportedByIssuer
  case responseEncryptionMethodNotSupportedByIssuer
  
  case invalidToken
  case issuanceRequestFailed(error: String, errorDescription: String?)
  case invalidTransactionId
  case unsupportedCredentialType
  case unsupportedCredentialFormat
  case invalidEncryptionParameters
  case invalidProof(cNonce: String, cNonceExpiresIn: Int?, errorDescription: String?)
  case deferredCredentialIssuancePending(interval: Int?)
  case notificationFailed(reason: String)
  
  public var errorDescription: String? {
    switch self {
    case .pushedAuthorizationRequestFailed(_, let errorDescription),
        .accessTokenRequestFailed(_, let errorDescription),
        .issuanceRequestFailed(_, let errorDescription),
        .invalidProof(_, _, let errorDescription):
      return errorDescription
    case .issuerDoesNotSupportBatchIssuance:
      return "Issuer does not support batch issuance"
    case .responseUnparsable(let details):
      return "Response is unparsable. Details: \(details)"
    case .invalidIssuanceRequest(let details):
      return "Invalid issuance request. Details: \(details)"
    case .cryptographicSuiteNotSupported(let name):
      return "Cryptographic suite not supported: \(name)"
    case .cryptographicBindingMethodNotSupported:
      return "Cryptographic binding method not supported."
    case .proofTypeNotSupported:
      return "Proof type not supported"
    case .cryptographicAlgorithmNotSupported:
      return "Cryptographic algorithm not supported."
    case .issuerDoesNotSupportEncryptedResponses:
      return "Issuer does not support encrypted responses."
    case .responseEncryptionAlgorithmNotSupportedByIssuer:
      return "Response encryption algorithm not supported by issuer."
    case .responseEncryptionMethodNotSupportedByIssuer:
      return "Response encryption method not supported by issuer."
    case .invalidToken:
      return "Invalid token."
    case .invalidTransactionId:
      return "Invalid transaction ID."
    case .unsupportedCredentialType:
      return "Unsupported credential type."
    case .unsupportedCredentialFormat:
      return "Unsupported credential format."
    case .invalidEncryptionParameters:
      return "Invalid encryption parameters."
    case .deferredCredentialIssuancePending(let interval):
      if let interval = interval {
        return "Deferred credential issuance pending. Retry in \(interval) seconds."
      } else {
        return "Deferred credential issuance pending."
      }
    case .notificationFailed(let reason):
      return "Notification failed: \(reason)"
    }
  }
}
