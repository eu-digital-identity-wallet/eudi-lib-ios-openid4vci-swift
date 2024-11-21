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

public struct SingleIssuanceSuccessResponse: Codable {
  public let credential: JSON?
  public let credentials: JSON?
  public let transactionId: String?
  public let notificationId: String?
  public let cNonce: String?
  public let cNonceExpiresInSeconds: Int?
  
  enum CodingKeys: String, CodingKey {
    case credential = "credential"
    case credentials = "credentials"
    case transactionId = "transaction_id"
    case notificationId = "notification_id"
    case cNonce = "c_nonce"
    case cNonceExpiresInSeconds = "c_nonce_expires_in"
  }
  
  public init(
    credential: JSON?,
    credentials: JSON?,
    transactionId: String?,
    notificationId: String?,
    cNonce: String?,
    cNonceExpiresInSeconds: Int?
  ) {
    self.credential = credential
    self.credentials = credentials
    self.transactionId = transactionId
    self.notificationId = notificationId
    self.cNonce = cNonce
    self.cNonceExpiresInSeconds = cNonceExpiresInSeconds
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    
    // Decode fields
    credential = try container.decodeIfPresent(JSON.self, forKey: .credential)
    credentials = try container.decodeIfPresent(JSON.self, forKey: .credentials)
    transactionId = try container.decodeIfPresent(String.self, forKey: .transactionId)
    notificationId = try container.decodeIfPresent(String.self, forKey: .notificationId)
    cNonce = try container.decodeIfPresent(String.self, forKey: .cNonce)
    cNonceExpiresInSeconds = try container.decodeIfPresent(Int.self, forKey: .cNonceExpiresInSeconds)
  
    if transactionId == nil && (credential == nil && credentials == nil) {
      throw DecodingError.dataCorruptedError(
        forKey: .credential,
        in: container,
        debugDescription: "At least one of 'credential' or 'credentials' must be non-nil."
      )
    }
    
    if notificationId != nil && (credential == nil && credentials == nil) {
      throw DecodingError.dataCorruptedError(
        forKey: .notificationId,
        in: container,
        debugDescription: "'notificationId' must not be present if 'credential' is not present."
      )
    }
  }
}

public extension SingleIssuanceSuccessResponse {
  
  func toDomain() throws -> CredentialIssuanceResponse {
    if let transactionId = transactionId {
      return .init(
        credentialResponses: [
          .deferred(transactionId: try .init(value: transactionId))
        ],
        cNonce: .init(
          value: cNonce,
          expiresInSeconds: cNonceExpiresInSeconds
        )
      )
    } else if let credential = credential,
              let string = credential.string {
      return .init(
        credentialResponses: [
          .issued(
            format: nil,
            credential: .string(string),
            notificationId: nil,
            additionalInfo: nil
          )
        ],
        cNonce: .init(
          value: cNonce,
          expiresInSeconds: cNonceExpiresInSeconds
        )
      )
    } else if let credentials = credentials,
              let jsonObject = credentials.array,
              !jsonObject.isEmpty {
      return .init(
        credentialResponses: [
          .issued(
            format: nil,
            credential: .json(JSON(jsonObject)),
            notificationId: nil,
            additionalInfo: nil
          )
        ],
        cNonce: .init(
          value: cNonce,
          expiresInSeconds: cNonceExpiresInSeconds
        )
      )
    } else {
      throw ValidationError.error(reason: "CredentialIssuanceResponse unparseable")
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
