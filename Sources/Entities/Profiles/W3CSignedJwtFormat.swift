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

public struct W3CSignedJwtFormat: FormatProfile {
  
  static let FORMAT = "jwt_vc_json"
  
  public let credentialDefinition: CredentialDefinition
  public let scope: String?
  
  enum CodingKeys: String, CodingKey {
    case credentialDefinition = "credential_definition"
    case scope
  }
  
  public init(credentialDefinition: CredentialDefinition, scope: String?) {
    self.credentialDefinition = credentialDefinition
    self.scope = scope
  }
}

public extension W3CSignedJwtFormat {
  
  struct W3CSignedJwtClaimSet: Codable {
    public let claims: [ClaimName: Claim]
    
    public init(claims: [ClaimName : Claim]) {
      self.claims = claims
    }
  }
  
  struct CredentialDefinitionTO: Codable {
    public let type: [String]
    public let credentialSubject: [String: Claim]?
    
    enum CodingKeys: String, CodingKey {
      case type = "type"
      case credentialSubject = "credential_subject"
    }
    
    public init(type: [String], credentialSubject: [String : Claim]?) {
      self.type = type
      self.credentialSubject = credentialSubject
    }
    
    public init(json: JSON) {
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
        type: type,
        credentialSubject: credentialSubject
      )
    }
  }
  
  struct CredentialConfigurationDTO: Codable {
    public let format: String
    public let scope: String?
    public let cryptographicBindingMethodsSupported: [String]?
    public let credentialSigningAlgValuesSupported: [String]?
    public let proofTypesSupported: [String: ProofSigningAlgorithmsSupported]?
    public let display: [Display]?
    public let credentialDefinition: CredentialDefinitionTO
    public let order: [String]?
    
    enum CodingKeys: String, CodingKey {
      case format
      case scope
      case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
      case credentialSigningAlgValuesSupported = "credential_signing_alg_values_supported"
      case proofTypesSupported = "proof_types_supported"
      case display
      case credentialDefinition = "credential_definition"
      case order
    }
    
    public init(
      format: String,
      scope: String? = nil,
      cryptographicBindingMethodsSupported: [String]? = nil,
      credentialSigningAlgValuesSupported: [String]? = nil,
      proofTypesSupported: [String: ProofSigningAlgorithmsSupported]? = nil,
      display: [Display]? = nil,
      credentialDefinition: CredentialDefinitionTO,
      order: [String]? = nil
    ) {
      self.format = format
      self.scope = scope
      self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
      self.credentialSigningAlgValuesSupported = credentialSigningAlgValuesSupported
      self.proofTypesSupported = proofTypesSupported
      self.display = display
      self.credentialDefinition = credentialDefinition
      self.order = order
    }
    
    func toDomain() throws -> W3CSignedJwtFormat.CredentialConfiguration {
      
      let bindingMethods = try cryptographicBindingMethodsSupported?.compactMap {
        try CryptographicBindingMethod(method: $0)
      } ?? []
      let display: [Display] = self.display ?? []
      
      let credentialSigningAlgValuesSupported: [String] = self.credentialSigningAlgValuesSupported ?? []
      let credentialDefinition = self.credentialDefinition.toDomain()
      
      return .init(
        scope: scope,
        cryptographicBindingMethodsSupported: bindingMethods,
        credentialSigningAlgValuesSupported: credentialSigningAlgValuesSupported,
        proofTypesSupported: proofTypesSupported,
        display: display,
        credentialDefinition: credentialDefinition,
        order: order ?? []
      )
    }
  }
  
  struct CredentialConfiguration: Codable {
    public let scope: String?
    public let cryptographicBindingMethodsSupported: [CryptographicBindingMethod]
    public let credentialSigningAlgValuesSupported: [String]
    public let proofTypesSupported: [String: ProofSigningAlgorithmsSupported]?
    public let display: [Display]
    public let credentialDefinition: CredentialDefinition
    public let order: [ClaimName]
    
    enum CodingKeys: String, CodingKey {
      case scope
      case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
      case credentialSigningAlgValuesSupported = "credential_signing_alg_values_supported"
      case proofTypesSupported = "proof_types_supported"
      case display
      case credentialDefinition = "credential_definition"
      case order
    }
    
    public init(
      scope: String?,
      cryptographicBindingMethodsSupported: [CryptographicBindingMethod],
      credentialSigningAlgValuesSupported: [String],
      proofTypesSupported: [String: ProofSigningAlgorithmsSupported]?,
      display: [Display],
      credentialDefinition: CredentialDefinition,
      order: [ClaimName]
    ) {
      self.scope = scope
      self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
      self.credentialSigningAlgValuesSupported = credentialSigningAlgValuesSupported
      self.proofTypesSupported = proofTypesSupported
      self.display = display
      self.credentialDefinition = credentialDefinition
      self.order = order
    }
    
    public init(from decoder: Decoder) throws {
      let container = try decoder.container(keyedBy: CodingKeys.self)
      
      scope = try container.decodeIfPresent(String.self, forKey: .scope)
      cryptographicBindingMethodsSupported = try container.decode([CryptographicBindingMethod].self, forKey: .cryptographicBindingMethodsSupported)
      credentialSigningAlgValuesSupported = try container.decode([String].self, forKey: .credentialSigningAlgValuesSupported)
      proofTypesSupported = try? container.decode([String: ProofSigningAlgorithmsSupported].self, forKey: .proofTypesSupported)
      display = try container.decode([Display].self, forKey: .display)
      credentialDefinition = try container.decode(CredentialDefinition.self, forKey: .credentialDefinition)
      order = try container.decode([ClaimName].self, forKey: .order)
    }
    
    public func encode(to encoder: Encoder) throws {
      var container = encoder.container(keyedBy: CodingKeys.self)
      
      try container.encode(scope, forKey: .scope)
      try container.encode(cryptographicBindingMethodsSupported, forKey: .cryptographicBindingMethodsSupported)
      try container.encode(credentialSigningAlgValuesSupported, forKey: .credentialSigningAlgValuesSupported)
      try container.encode(proofTypesSupported, forKey: .proofTypesSupported)
      try container.encode(display, forKey: .display)
      try container.encode(credentialDefinition, forKey: .credentialDefinition)
      try container.encode(order, forKey: .order)
    }
    
    init(json: JSON) throws {
      self.scope = json["scope"].string
      self.cryptographicBindingMethodsSupported = try json["cryptographic_binding_methods_supported"].arrayValue.map {
        try CryptographicBindingMethod(method: $0.stringValue)
      }
      self.credentialSigningAlgValuesSupported = json["credential_signing_alg_values_supported"].arrayValue.map {
        $0.stringValue
      }
      self.proofTypesSupported = json["proof_types_supported"].dictionaryObject?.compactMapValues { values in
        if let types = values as? [String: Any],
           let algorithms = types["proof_signing_alg_values_supported"] as? [String] {
          return ProofSigningAlgorithmsSupported(algorithms: algorithms)
        }
        return nil
      }
      self.display = json["display"].arrayValue.map { json in
        Display(json: json)
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
    public let type: [String]
    public let credentialSubject: [ClaimName: Claim?]?
    
    enum CodingKeys: String, CodingKey {
      case type
      case credentialSubject
    }
    
    public init(type: [String], credentialSubject: [ClaimName : Claim?]?) {
      self.type = type
      self.credentialSubject = credentialSubject
    }
    
    public init(json: JSON) {
      self.type = json["type"].arrayValue.map { $0.stringValue }
      
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

public extension W3CSignedJwtFormat {
  
  static func matchSupportedAndToDomain(
    json: JSON,
    metadata: CredentialIssuerMetadata
  ) throws -> CredentialMetadata {
    
    let credentialDefinition = CredentialDefinitionTO(json: json).toDomain()
    
    if let credentialConfigurationsSupported = metadata.credentialsSupported.first(where: { (id, credential) in
      switch credential {
      case .w3CSignedJwt(let credentialConfiguration):
        return credentialConfiguration.credentialDefinition.type == credentialDefinition.type
      default: return false
      }
    }) {
      switch credentialConfigurationsSupported.value {
      case .w3CSignedJwt(let profile):
        return .w3CSignedJwt(.init(
          credentialDefinition: credentialDefinition,
          scope: profile.scope
        )
      )
      default: break
      }
    }
    throw ValidationError.error(reason: "Unable to parse a list of supported credentials for W3CJsonLdSignedJwtProfile")
  }
}
