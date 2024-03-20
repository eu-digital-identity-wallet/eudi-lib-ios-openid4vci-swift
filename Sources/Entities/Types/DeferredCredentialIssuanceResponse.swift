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

public enum DeferredCredentialIssuanceResponse: Codable {
  case issued(format: String?, credential: String)
  case issuancePending(transactionId: TransactionId)
  case errored(error: String?, errorDescription: String?)
  
  private enum CodingKeys: String, CodingKey {
    case type
    case format
    case credential
    case transactionId = "transaction_id"
    case error
    case errorDescription = "error_description"
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    if let format = try? container.decode(String.self, forKey: .format),
       let credential = try? container.decode(String.self, forKey: .credential) {
      self = .issued(format: format, credential: credential)
      
    } else if let transactionId = try? container.decode(String.self, forKey: .transactionId) {
      self = .issuancePending(transactionId: try .init(value: transactionId))
      
    } else if let credential = try? container.decode(String.self, forKey: .credential) {
       self = .issued(
        format: nil,
        credential: credential
       )
       
     } else {
      self = .errored(
        error: try? container.decode(String.self, forKey: .error),
        errorDescription: try? container.decodeIfPresent(String.self, forKey: .errorDescription)
      )
    }
  }
  
  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    
    switch self {
    case let .issued(format, credential):
      try container.encode("issued", forKey: .type)
      try container.encode(format, forKey: .format)
      try container.encode(credential, forKey: .credential)
      
    case let .issuancePending(transactionId):
      try container.encode("issuancePending", forKey: .type)
      try container.encode(transactionId, forKey: .transactionId)
      
    case let .errored(error, errorDescription):
      try container.encode("errored", forKey: .type)
      try container.encode(error, forKey: .error)
      try container.encode(errorDescription, forKey: .errorDescription)
    }
  }
}

