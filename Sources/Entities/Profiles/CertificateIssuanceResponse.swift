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

public struct CertificateIssuanceResponse: Codable {
  public let credential: String?
  public let transactionId: String?
  public let notificationId: String?
  
  enum CodingKeys: String, CodingKey {
    case credential
    case transactionId = "transaction_id"
    case notificationId = "notification_id"
  }
  
  public init(
    credential: String?,
    transactionId: String?,
    notificationId: String?
  ) {
    self.credential = credential
    self.transactionId = transactionId
    self.notificationId = notificationId
  }
}
