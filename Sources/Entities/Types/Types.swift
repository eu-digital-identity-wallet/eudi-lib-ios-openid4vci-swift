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

public struct IssuanceResponseEncryptionSpec {
  public let jwk: JWK?
  public let privateKey: SecKey?
  public let algorithm: JWEAlgorithm
  public let encryptionMethod: JOSEEncryptionMethod
  
  public init(
    jwk: JWK? = nil,
    privateKey: SecKey?,
    algorithm: JWEAlgorithm,
    encryptionMethod: JOSEEncryptionMethod
  ) {
    self.jwk = jwk
    self.privateKey = privateKey
    self.algorithm = algorithm
    self.encryptionMethod = encryptionMethod
  }
}

public enum Proof: Codable {
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
  
  // MARK: - Codable
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    
    if let jwt = try? container.decode(JWT.self) {
      self = .jwt(jwt)
    } else if let cwt = try? container.decode(String.self) {
      self = .cwt(cwt)
    } else {
      throw DecodingError.typeMismatch(Proof.self, DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Invalid proof type"))
    }
  }
  
  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    
    switch self {
    case .jwt(let jwt):
      try container.encode([
        "proof_type": "jwt",
        "jwt": jwt
      ])
    case .cwt(let cwt):
      try container.encode(cwt)
    }
  }
  
  public func toDictionary() throws -> [String: String] {
    switch self {
    case .jwt(let jwt):
      return [
        "proof_type": "jwt",
        "jwt": jwt
      ]
    case .cwt:
      throw ValidationError.error(reason: "CWT not supported yet")
    }
  }
}

public struct Scope: Codable {
  public let value: String
  
  public init(_ value: String?) throws {
    
    guard let value = value else {
      throw ValidationError.error(reason: "Scope cannot be nil")
    }
    
    guard !value.isEmpty else {
      throw ValidationError.error(reason: "Scope cannot be empty")
    }
    self.value = value
  }
}

public enum ContentType: String {
  case key = "Content-Type"
  case form = "application/x-www-form-urlencoded; charset=UTF-8"
  case json = "application/json"
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

public struct DeferredIssuanceRequestTO: Codable {
  public let transactionId: String
  
  private enum CodingKeys: String, CodingKey {
    case transactionId = "transaction_id"
  }
  
  public init(transactionId: String) {
    self.transactionId = transactionId
  }
}
