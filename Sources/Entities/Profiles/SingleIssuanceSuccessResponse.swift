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

public struct SingleIssuanceSuccessResponse: Codable {
  public let format: String?
  public let credential: String?
  public let transactionId: String?
  public let notificationId: String?
  public let cNonce: String?
  public let cNonceExpiresInSeconds: Int?
  
  enum CodingKeys: String, CodingKey {
    case format
    case credential
    case transactionId = "transaction_id"
    case notificationId = "notification_id"
    case cNonce = "c_nonce"
    case cNonceExpiresInSeconds = "c_nonce_expires_in"
  }
  
  public init(
    format: String?,
    credential: String?,
    transactionId: String?,
    notificationId: String?,
    cNonce: String?,
    cNonceExpiresInSeconds: Int?
  ) {
    self.format = format
    self.credential = credential
    self.transactionId = transactionId
    self.notificationId = notificationId
    self.cNonce = cNonce
    self.cNonceExpiresInSeconds = cNonceExpiresInSeconds
  }
}

public extension SingleIssuanceSuccessResponse {
  
  func toDomain() throws -> CredentialIssuanceResponse {
    if let transactionId = transactionId {
      return CredentialIssuanceResponse(
        credentialResponses: [.deferred(transactionId: try .init(value: transactionId))],
        cNonce: CNonce(value: cNonce, expiresInSeconds: cNonceExpiresInSeconds)
      )
    } else if let credential = credential {
      return CredentialIssuanceResponse(
        credentialResponses: [.issued(format: format ?? "", credential: credential, notificationId: nil)],
        cNonce: CNonce(value: cNonce, expiresInSeconds: cNonceExpiresInSeconds)
      )
    } else {
      throw ValidationError.error(reason: "CredentialIssuanceResponse unpareable")
    }
  }
  
  static func fromJSONString(_ jsonString: String) -> SingleIssuanceSuccessResponse? {
    guard let jsonData = jsonString.data(using: .utf8) else {
      return nil
    }
    
    do {
      let yourObject = try JSONDecoder().decode(SingleIssuanceSuccessResponse.self, from: jsonData)
      return yourObject
    } catch {
      return nil
    }
  }
}
