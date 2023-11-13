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
import JOSESwift

public typealias JWT = String

public enum Proof {
  case jwt(JWT)
  case cwt(String)
  
  public func type() -> ProofType {
    switch self {
    case .jwt:
      return .jwt
    case .cwt:
      return .cwt
    }
  }
}

public struct Scope: Codable {
  public let value: String
  
  public init(value: String) throws {
    guard !value.isEmpty else {
      throw ValidationError.error(reason: "Scope cannot be empty")
    }
    self.value = value
  }
}

public enum ContentType: String {
  case key = "Content-Type"
  case form = "application/x-www-form-urlencoded; charset=UTF-8"
}

public struct CNonce: Codable {
  public let value: String
  public let expiresInSeconds: Int?
  
  public init?(value: String?, expiresInSeconds: Int? = 5) {
    guard let value else { return nil }
    precondition(!value.isEmpty, "Value cannot be empty")
    
    self.value = value
    self.expiresInSeconds = expiresInSeconds
  }
}

public struct SingleIssuanceSuccessResponse: Codable {
  public let format: String
  public let credential: String?
  public let transactionId: String?
  public let cNonce: String?
  public let cNonceExpiresInSeconds: Int?
  
  public init(format: String, credential: String?, transactionId: String?, cNonce: String?, cNonceExpiresInSeconds: Int?) {
    self.format = format
    self.credential = credential
    self.transactionId = transactionId
    self.cNonce = cNonce
    self.cNonceExpiresInSeconds = cNonceExpiresInSeconds
  }
}

public struct GenericErrorResponse: Codable {
  public let error: String
  public let errorDescription: String?
  public let cNonce: String?
  public let cNonceExpiresInSeconds: Int?
  public let interval: Int?
  
  public init(error: String, errorDescription: String?, cNonce: String?, cNonceExpiresInSeconds: Int?, interval: Int?) {
    self.error = error
    self.errorDescription = errorDescription
    self.cNonce = cNonce
    self.cNonceExpiresInSeconds = cNonceExpiresInSeconds
    self.interval = interval
  }
}

public struct BatchIssuanceSuccessResponse: Codable {
  public let credentialResponses: [CertificateIssuanceResponse]
  public let cNonce: String?
  public let cNonceExpiresInSeconds: Int?
  
  public struct CertificateIssuanceResponse: Codable {
    public let format: String
    public let credential: String?
    public let transactionId: String?
    
    public init(format: String, credential: String?, transactionId: String?) {
      self.format = format
      self.credential = credential
      self.transactionId = transactionId
    }
  }
  
  public init(credentialResponses: [CertificateIssuanceResponse], cNonce: String?, cNonceExpiresInSeconds: Int?) {
    self.credentialResponses = credentialResponses
    self.cNonce = cNonce
    self.cNonceExpiresInSeconds = cNonceExpiresInSeconds
  }
}

public struct Claim: Codable {
  public let mandatory: Bool?
  public let valueType: String?
  public let display: [Display]?
  
  enum CodingKeys: String, CodingKey {
    case mandatory
    case valueType = "value_type"
    case display
  }
  
  public init(mandatory: Bool?, valueType: String?, display: [Display]?) {
    self.mandatory = mandatory
    self.valueType = valueType
    self.display = display
  }
  
  init(json: JSON) {
    mandatory = json["mandatory"].bool
    valueType = json["value_type"].string
    
    if let displayArray = json["display"].array {
      display = displayArray.map { displayJson in
        Display(json: displayJson)
      }
    } else {
      display = nil
    }
  }
}
