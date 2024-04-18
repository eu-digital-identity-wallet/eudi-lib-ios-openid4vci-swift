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

public struct CredentialIssuanceResponse: Codable {
  public let credentialResponses: [Result]
  public let cNonce: CNonce?
  
  public enum Result: Codable {
    case deferred(transactionId: TransactionId)
    case issued(format: String?, credential: String, notificationId: NotificationId?)
  }
  
  public init(credentialResponses: [Result], cNonce: CNonce?) {
    self.credentialResponses = credentialResponses
    self.cNonce = cNonce
  }
}

public enum SubmittedRequest {
  case success(response: CredentialIssuanceResponse)
  case failed(error: CredentialIssuanceError)
  case invalidProof(cNonce: CNonce, errorDescription: String?)
  
  var credentials: [String] {
    switch self {
    case .success(let response):
      response.credentialResponses.compactMap { result in
        switch result {
        case .issued(_, let credential, _):
          credential
        default:
          nil
        }
      }
    default:
      []
    }
  }
}
