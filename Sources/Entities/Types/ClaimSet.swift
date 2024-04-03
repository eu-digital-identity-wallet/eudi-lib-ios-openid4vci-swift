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

public enum ClaimSet: Codable {
  case w3CJsonLdDataIntegrity(W3CJsonLdDataIntegrityFormat.W3CJsonLdDataIntegrityClaimSet)
  case w3CJsonLdSignedJwt(W3CJsonLdSignedJwtFormat.W3CJsonLdSignedJwtClaimSet)
  case w3CSignedJwt(W3CSignedJwtFormat.W3CSignedJwtClaimSet)
  case msoMdoc(MsoMdocFormat.MsoMdocClaimSet?)
  case sdJwtVc(SdJwtVcFormat.SdJwtVcClaimSet?)
  case generic(GenericClaimSet?)
  
  public func toDictionary() -> [String: JSON]? {
    switch self {
    case .w3CJsonLdDataIntegrity,
         .w3CJsonLdSignedJwt,
         .w3CSignedJwt:
      return nil
    case .msoMdoc(let claimSet):
      guard let claims = claimSet?.claims else {
        return nil
      }
      
      let elements = Dictionary(grouping: claims) { key, _ in
          return key
      }.values.flatMap { $0 }.map { $0.1 }

      return Dictionary(uniqueKeysWithValues: elements.map { ($0, JSON()) })
      
    case .sdJwtVc(_):
      return nil
    case .generic(let claimSet):
      guard let claims = claimSet?.claims else {
        return nil
      }
      return Dictionary(uniqueKeysWithValues: claims.map { ($0, JSON()) })
    }
  }
  
  public func validate(credentialSupported: CredentialSupported) -> ClaimSet? {
    switch self {
    case .w3CJsonLdDataIntegrity(_):
      return nil
    case .w3CJsonLdSignedJwt(_):
      return nil
    case .w3CSignedJwt(_):
      return nil
    case .msoMdoc(let claimSet):
      guard let claims = claimSet?.claims else {
        return nil
      }
      if !claims.isEmpty {
        for (nameSpace, claimName) in claims {
          
        }
        return .msoMdoc(claimSet)
      } else {
        return nil
      }
      
    case .sdJwtVc(_):
      return nil
      
    case .generic(_):
      return nil
    }
  }
}

public extension ClaimSet {
  
  init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    
    if let claimSet = try? container.decode(W3CJsonLdDataIntegrityFormat.W3CJsonLdDataIntegrityClaimSet.self) {
      self = .w3CJsonLdDataIntegrity(claimSet)
    } else if let claimSet = try? container.decode(W3CJsonLdSignedJwtFormat.W3CJsonLdSignedJwtClaimSet.self) {
      self = .w3CJsonLdSignedJwt(claimSet)
    } else if let claimSet = try? container.decode(W3CSignedJwtFormat.W3CSignedJwtClaimSet.self) {
      self = .w3CSignedJwt(claimSet)
    } else if let claimSet = try? container.decode(MsoMdocFormat.MsoMdocClaimSet.self) {
      self = .msoMdoc(claimSet)
    } else if let claimSet = try? container.decode(SdJwtVcFormat.SdJwtVcClaimSet.self) {
      self = .sdJwtVc(claimSet)
    } else {
      throw DecodingError.typeMismatch(ClaimSet.self, DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Invalid claim set type"))
    }
  }
  
  func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    
    switch self {
    case .w3CJsonLdDataIntegrity(let claimSet):
      try container.encode(claimSet)
    case .w3CJsonLdSignedJwt(let claimSet):
      try container.encode(claimSet)
    case .w3CSignedJwt(let claimSet):
      try container.encode(claimSet)
    case .msoMdoc(let claimSet):
      try container.encode(claimSet)
    case .sdJwtVc(let claimSet):
      try container.encode(claimSet)
    case .generic(let claimSet):
      try container.encode(claimSet)
    }
  }
}
