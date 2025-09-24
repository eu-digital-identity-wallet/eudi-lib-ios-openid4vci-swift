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

public struct W3CJsonLdSignedJwtFormat: FormatProfile {
  
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

public extension W3CJsonLdSignedJwtFormat {
  
  struct CredentialDefinitionTO: Codable {
    public let context: [String]
    public let type: [String]
    public let claims: [Claim]
    
    enum CodingKeys: String, CodingKey {
      case context = "@context"
      case type
      case claims
    }
    
    public init(
      context: [String],
      type: [String],
      claims: [Claim]
    ) {
      self.context = context
      self.type = type
      self.claims = claims
    }
    
    public init(json: JSON) throws {
      context = json["@context"].arrayValue.map { $0.stringValue }
      type = json["type"].arrayValue.map { $0.stringValue }
      
      let claims = try json["claims"].array?.compactMap({ try Claim(json: $0)}) ?? []
      self.claims = claims
    }
    
    func toDomain() -> CredentialDefinition {
      CredentialDefinition(
        context: context,
        type: type,
        claims: claims
      )
    }
  }
  
  struct CredentialConfigurationDTO: Codable {
    public let format: String
    public let scope: String?
    public let cryptographicBindingMethodsSupported: [String]?
    public let credentialSigningAlgValuesSupported: [String]?
    public let proofTypesSupported: [String: ProofTypeSupportedMeta]?
    public let credentialMetadata: ConfigurationCredentialMetadata?
    public let context: [String]
    public let credentialDefinition: CredentialDefinitionTO
    
    enum CodingKeys: String, CodingKey {
      case format
      case scope
      case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
      case credentialSigningAlgValuesSupported = "credential_signing_alg_values_supported"
      case proofTypesSupported = "proof_types_supported"
      case credentialMetadata = "credential_metadata"
      case context = "@context"
      case credentialDefinition = "credential_definition"
    }
    
    public init(
      format: String,
      scope: String? = nil,
      cryptographicBindingMethodsSupported: [String]? = nil,
      credentialSigningAlgValuesSupported: [String]? = nil,
      proofTypesSupported: [String: ProofTypeSupportedMeta]? = nil,
      credentialMetadata: ConfigurationCredentialMetadata? = nil,
      context: [String] = [],
      credentialDefinition: CredentialDefinitionTO
    ) {
      self.format = format
      self.scope = scope
      self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
      self.credentialSigningAlgValuesSupported = credentialSigningAlgValuesSupported
      self.proofTypesSupported = proofTypesSupported
      self.credentialMetadata = credentialMetadata
      self.context = context
      self.credentialDefinition = credentialDefinition
    }
    
    func toDomain() throws -> W3CJsonLdSignedJwtFormat.CredentialConfiguration {
      
      let bindingMethods = try cryptographicBindingMethodsSupported?.compactMap {
        try CryptographicBindingMethod(method: $0)
      } ?? []
      let context: [String] = self.context
      
      let credentialSigningAlgValuesSupported: [String] = self.credentialSigningAlgValuesSupported ?? []
      let credentialDefinition = self.credentialDefinition.toDomain()
      
      return .init(
        scope: scope,
        cryptographicBindingMethodsSupported: bindingMethods,
        credentialSigningAlgValuesSupported: credentialSigningAlgValuesSupported,
        proofTypesSupported: proofTypesSupported,
        credentialMetadata: credentialMetadata,
        context: context,
        credentialDefinition: credentialDefinition
      )
    }
  }
  
  struct CredentialConfiguration: Codable, Sendable {
    public let scope: String?
    public let cryptographicBindingMethodsSupported: [CryptographicBindingMethod]
    public let credentialSigningAlgValuesSupported: [String]
    public let proofTypesSupported: [String: ProofTypeSupportedMeta]?
    public let credentialMetadata: ConfigurationCredentialMetadata?
    public let context: [String]
    public let credentialDefinition: CredentialDefinition
    
    enum CodingKeys: String, CodingKey {
      case scope
      case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
      case credentialSigningAlgValuesSupported = "credential_signing_alg_values_supported"
      case proofTypesSupported = "proof_types_supported"
      case credentialMetadata = "credential_metadata"
      case context = "@context"
      case credentialDefinition = "credential_definition"
    }
    
    public init(
      scope: String?,
      cryptographicBindingMethodsSupported: [CryptographicBindingMethod],
      credentialSigningAlgValuesSupported: [String],
      proofTypesSupported: [String: ProofTypeSupportedMeta]?,
      credentialMetadata: ConfigurationCredentialMetadata?,
      context: [String],
      credentialDefinition: CredentialDefinition
    ) {
      self.scope = scope
      self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
      self.credentialSigningAlgValuesSupported = credentialSigningAlgValuesSupported
      self.proofTypesSupported = proofTypesSupported
      self.credentialMetadata = credentialMetadata
      self.context = context
      self.credentialDefinition = credentialDefinition
    }
    
    public init(from decoder: Decoder) throws {
      let container = try decoder.container(keyedBy: CodingKeys.self)
      
      scope = try container.decodeIfPresent(String.self, forKey: .scope)
      cryptographicBindingMethodsSupported = try container.decode([CryptographicBindingMethod].self, forKey: .cryptographicBindingMethodsSupported)
      credentialSigningAlgValuesSupported = try container.decode([String].self, forKey: .credentialSigningAlgValuesSupported)
      proofTypesSupported = try? container.decode([String: ProofTypeSupportedMeta]?.self, forKey: .proofTypesSupported)
      credentialMetadata = try container.decode(ConfigurationCredentialMetadata.self, forKey: .credentialMetadata)
      context = try container.decode([String].self, forKey: .context)
      credentialDefinition = try container.decode(CredentialDefinition.self, forKey: .credentialDefinition)
    }
    
    public func encode(to encoder: Encoder) throws {
      var container = encoder.container(keyedBy: CodingKeys.self)
      
      try container.encode(scope, forKey: .scope)
      try container.encode(cryptographicBindingMethodsSupported, forKey: .cryptographicBindingMethodsSupported)
      try container.encode(credentialSigningAlgValuesSupported, forKey: .credentialSigningAlgValuesSupported)
      try container.encode(proofTypesSupported, forKey: .proofTypesSupported)
      try container.encode(credentialMetadata, forKey: .credentialMetadata)
      try container.encode(context, forKey: .context)
      try container.encode(credentialDefinition, forKey: .credentialDefinition)
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
          let requirement = types["key_attestations_required"]
          return .init(
            algorithms: algorithms,
            keyAttestationRequirement: try? .init(json: JSON(requirement ?? [:]))
          )
        }
        return nil
      }
      self.credentialMetadata = try ConfigurationCredentialMetadata(json: json["credential_metadata"])
      self.context = json["@context"].arrayValue.map {
        $0.stringValue
      }
      self.credentialDefinition = try CredentialDefinition(json: json["credential_definition"])
    }
    
    func toIssuanceRequest(
      proofs: [Proof]
    ) throws -> CredentialIssuanceRequest {
      throw ValidationError.error(reason: "Not yet implemented")
    }
  }
  
  struct CredentialDefinition: Codable, Sendable {
    public let context: [String]
    public let type: [String]
    public let claims: [Claim]
    
    enum CodingKeys: String, CodingKey {
      case context = "@context"
      case type
      case claims
    }
    
    public init(
      context: [String],
      type: [String],
      claims: [Claim]
    ) {
      self.context = context
      self.type = type
      self.claims = claims
    }
    
    public init(json: JSON) throws {
      context = json["@context"].arrayValue.map { $0.stringValue }
      type = json["type"].arrayValue.map { $0.stringValue }
      
      let claims = try json["claims"].array?.compactMap({ try Claim(json: $0)}) ?? []
      self.claims = claims
    }
  }
}

public extension W3CJsonLdSignedJwtFormat {
  
  static func matchSupportedAndToDomain(
    json: JSON,
    metadata: CredentialIssuerMetadata
  ) throws -> CredentialMetadata {
    
    let credentialDefinition = try CredentialDefinitionTO(json: json).toDomain()
    
    if let credentialConfigurationsSupported = metadata.credentialsSupported.first(where: { (_, credential) in
      switch credential {
      case .w3CJsonLdSignedJwt(let credentialConfiguration):
        return credentialConfiguration.credentialDefinition.type == credentialDefinition.type
      default: return false
      }
    }) {
      switch credentialConfigurationsSupported.value {
      case .w3CJsonLdSignedJwt(let profile):
        
        // Validation: proof_types_supported must be present if cryptographic_binding_methods_supported is present
        if !profile.cryptographicBindingMethodsSupported.isEmpty {
          guard let proofTypes = profile.proofTypesSupported, !proofTypes.isEmpty else {
            throw ValidationError.error(reason: "Property `proof_types_supported` must be present if `cryptographic_binding_methods_supported` is present")
          }
        }
        
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
