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

public enum OfferedCredential: Codable {
  case msoMdocCredential(MsoMdocCredential)
  case w3CVerifiableCredential(W3CVerifiableCredential)
  
  enum CodingKeys: String, CodingKey {
    case msoMdocCredential
    case w3CVerifiableCredential
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    
    if container.contains(.msoMdocCredential) {
      self = .msoMdocCredential(try container.decode(MsoMdocCredential.self, forKey: .msoMdocCredential))
    } else if container.contains(.w3CVerifiableCredential) {
      self = .w3CVerifiableCredential(try container.decode(W3CVerifiableCredential.self, forKey: .w3CVerifiableCredential))
    } else {
      throw DecodingError.dataCorrupted(DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Invalid OfferedCredential"))
    }
  }
  
  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    
    switch self {
    case .msoMdocCredential(let msoMdocCredential):
      try container.encode(msoMdocCredential, forKey: .msoMdocCredential)
    case .w3CVerifiableCredential(let w3CVerifiableCredential):
      try container.encode(w3CVerifiableCredential, forKey: .w3CVerifiableCredential)
    }
  }
}

public enum W3CVerifiableCredential: Codable {
  case signedJwt(SignedJwt)
  case jsonLdSignedJwt(JsonLdSignedJwt)
  case jsonLdDataIntegrity(JsonLdDataIntegrity)
  
  enum CodingKeys: String, CodingKey {
    case signedJwt
    case jsonLdSignedJwt
    case jsonLdDataIntegrity
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    
    if container.contains(.signedJwt) {
      self = .signedJwt(try container.decode(SignedJwt.self, forKey: .signedJwt))
    } else if container.contains(.jsonLdSignedJwt) {
      self = .jsonLdSignedJwt(try container.decode(JsonLdSignedJwt.self, forKey: .jsonLdSignedJwt))
    } else if container.contains(.jsonLdDataIntegrity) {
      self = .jsonLdDataIntegrity(try container.decode(JsonLdDataIntegrity.self, forKey: .jsonLdDataIntegrity))
    } else {
      throw DecodingError.dataCorrupted(DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Invalid W3CVerifiableCredential"))
    }
  }
  
  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    
    switch self {
    case .signedJwt(let signedJwt):
      try container.encode(signedJwt, forKey: .signedJwt)
    case .jsonLdSignedJwt(let jsonLdSignedJwt):
      try container.encode(jsonLdSignedJwt, forKey: .jsonLdSignedJwt)
    case .jsonLdDataIntegrity(let jsonLdDataIntegrity):
      try container.encode(jsonLdDataIntegrity, forKey: .jsonLdDataIntegrity)
    }
  }
}

public struct SignedJwt: Codable {
  public let credentialDefinition: JSON
  public let scope: String?
  
  public init(credentialDefinition: JSON, scope: String?) {
    self.credentialDefinition = credentialDefinition
    self.scope = scope
  }
}

public struct JsonLdSignedJwt: Codable {
  public let credentialDefinition: JSON
  public let scope: String?
  
  public init(credentialDefinition: JSON, scope: String?) {
    self.credentialDefinition = credentialDefinition
    self.scope = scope
  }
}

public struct JsonLdDataIntegrity: Codable {
  public let credentialDefinition: JSON
  public let scope: String?
  
  public init(credentialDefinition: JSON, scope: String?) {
    self.credentialDefinition = credentialDefinition
    self.scope = scope
  }
}
