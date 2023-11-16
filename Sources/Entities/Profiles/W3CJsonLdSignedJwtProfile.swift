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

public struct W3CJsonLdSignedJwtProfile: Profile {
  
  static let FORMAT = "jwt_vc_json-ld"
  
  public let credentialDefinition: CredentialDefinition
  public let scope: String?
  public let content: [URL]
  public let type: [String]
  
  enum CodingKeys: String, CodingKey {
    case credentialDefinition = "credential_definition"
    case content
    case type
    case scope
  }
  
  public init(credentialDefinition: CredentialDefinition, scope: String?, content: [URL], type: [String]) {
    self.credentialDefinition = credentialDefinition
    self.scope = scope
    self.content = content
    self.type = type
  }
}

public extension W3CJsonLdSignedJwtProfile {
  
  struct W3CJsonLdSignedJwtClaimSet {
    public let claims: [ClaimName: Claim]
    
    public init(claims: [ClaimName : Claim]) {
      self.claims = claims
    }
  }
  
  struct CredentialDefinitionTO: Codable {
    public let context: [String]
    public let type: [String]
    public let credentialSubject: [String: Claim]?
    
    enum CodingKeys: String, CodingKey {
      case context = "@context"
      case type
      case credentialSubject = "credential_subject"
    }
    
    public init(
      context: [String],
      type: [String],
      credentialSubject: [String : Claim]?
    ) {
      self.context = context
      self.type = type
      self.credentialSubject = credentialSubject
    }
    
    public init(json: JSON) {
      context = json["@context"].arrayValue.map { $0.stringValue }
      type = json["type"].arrayValue.map { $0.stringValue }
      
      if let credentialSubjectDict = json["credential_subject"].dictionaryObject as? [String: [String: Any]] {
        credentialSubject = credentialSubjectDict.compactMapValues { claimDict in
          Claim(json: JSON(claimDict))
        }
      } else {
        credentialSubject = nil
      }
    }
    
    func toDomain() -> CredentialDefinition {
      CredentialDefinition(
        context: context,
        type: type,
        credentialSubject: credentialSubject
      )
    }
  }
  
  struct CredentialSupportedDTO: Codable {
    public let format: String
    public let scope: String?
    public let cryptographicBindingMethodsSupported: [String]?
    public let cryptographicSuitesSupported: [String]?
    public let proofTypesSupported: [String]?
    public let display: [Display]?
    public let context: [String]
    public let credentialDefinition: CredentialDefinitionTO
    public let order: [String]?
    
    enum CodingKeys: String, CodingKey {
      case format
      case scope
      case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
      case cryptographicSuitesSupported = "cryptographic_suites_supported"
      case proofTypesSupported = "proof_types_supported"
      case display
      case context = "@context"
      case credentialDefinition = "credential_definition"
      case order
    }
    
    public init(
      format: String,
      scope: String? = nil,
      cryptographicBindingMethodsSupported: [String]? = nil,
      cryptographicSuitesSupported: [String]? = nil,
      proofTypesSupported: [String]? = nil,
      display: [Display]? = nil,
      context: [String] = [],
      credentialDefinition: CredentialDefinitionTO,
      order: [String]? = nil
    ) {
      self.format = format
      self.scope = scope
      self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
      self.cryptographicSuitesSupported = cryptographicSuitesSupported
      self.proofTypesSupported = proofTypesSupported
      self.display = display
      self.context = context
      self.credentialDefinition = credentialDefinition
      self.order = order
    }
    
    func toDomain() throws -> W3CJsonLdSignedJwtProfile.CredentialSupported {
      
      let bindingMethods = try cryptographicBindingMethodsSupported?.compactMap {
        try CryptographicBindingMethod(method: $0)
      } ?? []
      let display: [Display] = self.display ?? []
      let context: [String] = self.context
      let proofTypesSupported: [ProofType] = try self.proofTypesSupported?.compactMap {
        try ProofType(type: $0)
      } ?? { throw ValidationError.error(reason: "No proof types found")}()
      let cryptographicSuitesSupported: [String] = self.cryptographicSuitesSupported ?? []
      let credentialDefinition = self.credentialDefinition.toDomain()
      
      return .init(
        scope: scope,
        cryptographicBindingMethodsSupported: bindingMethods,
        cryptographicSuitesSupported: cryptographicSuitesSupported,
        proofTypesSupported: proofTypesSupported,
        display: display, 
        context: context,
        credentialDefinition: credentialDefinition,
        order: order ?? []
      )
    }
  }
  
  struct CredentialSupported: Codable {
    public let scope: String?
    public let cryptographicBindingMethodsSupported: [CryptographicBindingMethod]
    public let cryptographicSuitesSupported: [String]
    public let proofTypesSupported: [ProofType]?
    public let display: [Display]
    public let context: [String]
    public let credentialDefinition: CredentialDefinition
    public let order: [ClaimName]
    
    enum CodingKeys: String, CodingKey {
      case scope
      case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
      case cryptographicSuitesSupported = "cryptographic_suites_supported"
      case proofTypesSupported = "proof_types_supported"
      case display
      case context = "@context"
      case credentialDefinition = "credential_definition"
      case order
    }
    
    public init(
      scope: String?,
      cryptographicBindingMethodsSupported: [CryptographicBindingMethod],
      cryptographicSuitesSupported: [String],
      proofTypesSupported: [ProofType]?,
      display: [Display],
      context: [String],
      credentialDefinition: CredentialDefinition,
      order: [ClaimName]
    ) {
      self.scope = scope
      self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
      self.cryptographicSuitesSupported = cryptographicSuitesSupported
      self.proofTypesSupported = proofTypesSupported
      self.display = display
      self.context = context
      self.credentialDefinition = credentialDefinition
      self.order = order
    }
    
    public init(from decoder: Decoder) throws {
      let container = try decoder.container(keyedBy: CodingKeys.self)
      
      scope = try container.decodeIfPresent(String.self, forKey: .scope)
      cryptographicBindingMethodsSupported = try container.decode([CryptographicBindingMethod].self, forKey: .cryptographicBindingMethodsSupported)
      cryptographicSuitesSupported = try container.decode([String].self, forKey: .cryptographicSuitesSupported)
      proofTypesSupported = try? container.decode([ProofType].self, forKey: .proofTypesSupported)
      display = try container.decode([Display].self, forKey: .display)
      context = try container.decode([String].self, forKey: .context)
      credentialDefinition = try container.decode(CredentialDefinition.self, forKey: .credentialDefinition)
      order = try container.decode([ClaimName].self, forKey: .order)
    }
    
    public func encode(to encoder: Encoder) throws {
      var container = encoder.container(keyedBy: CodingKeys.self)
      
      try container.encode(scope, forKey: .scope)
      try container.encode(cryptographicBindingMethodsSupported, forKey: .cryptographicBindingMethodsSupported)
      try container.encode(cryptographicSuitesSupported, forKey: .cryptographicSuitesSupported)
      try container.encode(proofTypesSupported, forKey: .proofTypesSupported)
      try container.encode(display, forKey: .display)
      try container.encode(context, forKey: .context)
      try container.encode(credentialDefinition, forKey: .credentialDefinition)
      try container.encode(order, forKey: .order)
    }
    
    init(json: JSON) throws {
      self.scope = json["scope"].string
      self.cryptographicBindingMethodsSupported = try json["cryptographic_binding_methods_supported"].arrayValue.map {
        try CryptographicBindingMethod(method: $0.stringValue)
      }
      self.cryptographicSuitesSupported = json["cryptographic_suites_supported"].arrayValue.map {
        $0.stringValue
      }
      self.proofTypesSupported = try json["proof_types_supported"].arrayValue.map {
        try ProofType(type: $0.stringValue)
      }
      self.display = json["display"].arrayValue.map { json in
        Display(json: json)
      }
      self.context = json["@context"].arrayValue.map {
        $0.stringValue
      }
      self.credentialDefinition = CredentialDefinition(json: json["credential_definition"])
      self.order = json["order"].arrayValue.map {
        ClaimName($0.stringValue)
      }
    }
    
    func toIssuanceRequest(
      claimSet: ClaimSet?,
      proof: Proof?
    ) throws -> CredentialIssuanceRequest {
      throw ValidationError.error(reason: "Not yet implemented")
    }
  }
  
  struct CredentialDefinition: Codable {
    public let context: [String]
    public let type: [String]
    public let credentialSubject: [ClaimName: Claim?]?
    
    enum CodingKeys: String, CodingKey {
      case context = "@context"
      case type
      case credentialSubject = "credential_subject"
    }
    
    public init(
      context: [String],
      type: [String],
      credentialSubject: [ClaimName : Claim?]?
    ) {
      self.context = context
      self.type = type
      self.credentialSubject = credentialSubject
    }
    
    public init(json: JSON) {
      context = json["@context"].arrayValue.map { $0.stringValue }
      type = json["type"].arrayValue.map { $0.stringValue }
      
      var credentialSubjectDict: [ClaimName: Claim?] = [:]
      let credentialSubjectJSON = json["credential_subject"]
      for (key, subJSON): (String, JSON) in credentialSubjectJSON.dictionaryValue {
        credentialSubjectDict[key] = Claim(
          mandatory: subJSON["mandatory"].bool,
          valueType: subJSON["valuetype"].string,
          display: subJSON["display"].arrayValue.compactMap {
            Display(json: $0)
          })
      }
      self.credentialSubject = credentialSubjectDict
    }
  }
}

public extension W3CJsonLdSignedJwtProfile {
  
  static func matchSupportedAndToDomain(
    json: JSON,
    metadata: CredentialIssuerMetadata
  ) throws -> CredentialMetadata {
    
    let credentialDefinition = CredentialDefinitionTO(json: json).toDomain()
    
    if let credentialsSupported = metadata.credentialsSupported.first(where: { credential in
      switch credential {
      case .w3CJsonLdSignedJwt(let credentialSupported):
        return credentialSupported.credentialDefinition.type == credentialDefinition.type
      default: return false
      }
    }) {
      switch credentialsSupported {
      case .w3CJsonLdSignedJwt(let profile):
        return .w3CJsonLdSignedJwt(.init(
          credentialDefinition: profile.credentialDefinition,
          scope: profile.scope,
          content: try credentialDefinition.context.map { string in try URL(string: string) ?? {
            throw ValidationError.error(reason: "Unable to parse url in @context \(string)")
          }()},
          type: credentialDefinition.type
        )
      )
      default: break
      }
    }
    throw ValidationError.error(reason: "Unable to parse a list of supported credentials for W3CJsonLdSignedJwtProfile")
  }
}
