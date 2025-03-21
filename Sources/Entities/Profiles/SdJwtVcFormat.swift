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
@preconcurrency import Foundation
import SwiftyJSON
@preconcurrency import JOSESwift

public struct SdJwtVcFormat: FormatProfile {
  
  static let FORMAT = "dc+sd-jwt"
  static let LEGACY_FORMAT = "vc+sd-jwt"
  
  public let type: String
  public let scope: String?
  
  enum CodingKeys: String, CodingKey {
    case type
    case scope
  }
  
  init(type: String, scope: String?) {
    self.type = type
    self.scope = scope
  }
}

public extension SdJwtVcFormat {
  
  struct SdJwtVcSingleCredential: Codable, Sendable {
    public let scope: String?
    public let proofs: [Proof]
    public let format: String = SdJwtVcFormat.FORMAT
    public let vct: String?
    public let credentialEncryptionJwk: JWK?
    public let credentialEncryptionKey: SecKey?
    public let credentialResponseEncryptionAlg: JWEAlgorithm?
    public let credentialResponseEncryptionMethod: JOSEEncryptionMethod?
    public let credentialDefinition: CredentialDefinition
    public let requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption
    public let credentialIdentifier: CredentialIdentifier?
    public let requestPayload: IssuanceRequestPayload
    public let display: [Display]
    
    enum CodingKeys: String, CodingKey {
      case scope
      case proof
      case format
      case credentialEncryptionJwk
      case credentialResponseEncryptionAlg
      case credentialResponseEncryptionMethod
      case credentialDefinition
      case credentialIdentifier
      case requestPayload
      case display
    }
    
    public init(
      scope: String?,
      proofs: [Proof],
      vct: String?,
      credentialEncryptionJwk: JWK? = nil,
      credentialEncryptionKey: SecKey? = nil,
      credentialResponseEncryptionAlg: JWEAlgorithm? = nil,
      credentialResponseEncryptionMethod: JOSEEncryptionMethod? = nil,
      credentialDefinition: CredentialDefinition,
      credentialIdentifier: CredentialIdentifier? = nil,
      requestPayload: IssuanceRequestPayload,
      display: [Display] = []
    ) throws {
      self.scope = scope
      self.proofs = proofs
      self.vct = vct
      self.credentialEncryptionJwk = credentialEncryptionJwk
      self.credentialEncryptionKey = credentialEncryptionKey
      self.credentialResponseEncryptionAlg = credentialResponseEncryptionAlg
      self.credentialResponseEncryptionMethod = credentialResponseEncryptionMethod
      self.credentialDefinition = .init(
        type: credentialDefinition.type,
        claims: credentialDefinition.claims
      )
      self.credentialIdentifier = credentialIdentifier
      self.requestPayload = requestPayload
      
      self.requestedCredentialResponseEncryption = try .init(
        encryptionJwk: credentialEncryptionJwk,
        encryptionKey: credentialEncryptionKey,
        responseEncryptionAlg: credentialResponseEncryptionAlg,
        responseEncryptionMethod: credentialResponseEncryptionMethod
      )
      
      self.display = display
    }
    
    public init(from decoder: Decoder) throws {
      fatalError("No supported yet")
    }
    
    public func encode(to encoder: Encoder) throws {
      var container = encoder.container(keyedBy: CodingKeys.self)
      try container.encode(proofs, forKey: .proof)
      
      if let credentialEncryptionJwk = credentialEncryptionJwk as? RSAPublicKey {
        try container.encode(credentialEncryptionJwk, forKey: .credentialEncryptionJwk)
      } else if let credentialEncryptionJwk = credentialEncryptionJwk as? ECPublicKey {
        try container.encode(credentialEncryptionJwk, forKey: .credentialEncryptionJwk)
      }
      
      try container.encode(credentialResponseEncryptionAlg, forKey: .credentialResponseEncryptionAlg)
      try container.encode(credentialResponseEncryptionMethod, forKey: .credentialResponseEncryptionMethod)
      
      try container.encode(credentialDefinition, forKey: .credentialDefinition)
      
      switch requestPayload {
      case .identifierBased(_, let credentialIdentifier):
        try container.encode(credentialIdentifier, forKey: .credentialIdentifier)
      case .configurationBased(let credentialConfigurationIdentifier):
        try container.encode(credentialConfigurationIdentifier, forKey: .credentialIdentifier)
      }
    }
    
    public struct CredentialDefinition: Codable, Sendable {
      public let type: String
      public let claims: [Claim]
      
      enum CodingKeys: String, CodingKey {
        case type
        case claims
      }
      
      public init(
        type: String,
        claims: [Claim]
      ) {
        self.type = type
        self.claims = claims
      }
    }
  }
  
  struct CredentialDefinitionTO: Codable {
    public let type: String
    public let claims: [Claim]
    
    enum CodingKeys: String, CodingKey {
      case type = "type"
      case claims = "claims"
    }
    
    public init(type: String, claims: [Claim]) {
      self.type = type
      self.claims = claims
    }
    
    public init(json: JSON) throws {
      type = json["type"].stringValue
      let claims = try json["claims"].array?.compactMap({ try Claim(json: $0)}) ?? []
      self.claims = claims
    }
    
    func toDomain() -> CredentialDefinition {
      .init(
        type: type,
        claims: claims
      )
    }
  }
  
  struct CredentialConfigurationDTO: Codable {
    public let format: String
    public let scope: String?
    public let vct: String?
    public let cryptographicBindingMethodsSupported: [String]?
    public let credentialSigningAlgValuesSupported: [String]?
    public let proofTypesSupported: [String: ProofTypeSupportedMeta]?
    public let display: [Display]?
    public let credentialDefinition: CredentialDefinitionTO
    public let claims: [Claim]
    
    enum CodingKeys: String, CodingKey {
      case format
      case scope
      case vct
      case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
      case credentialSigningAlgValuesSupported = "credential_signing_alg_values_supported"
      case proofTypesSupported = "proof_types_supported"
      case display
      case credentialDefinition = "credential_definition"
      case claims
    }
    
    public init(
      format: String,
      scope: String? = nil,
      vct: String? = nil,
      cryptographicBindingMethodsSupported: [String]? = nil,
      credentialSigningAlgValuesSupported: [String]? = nil,
      proofTypesSupported: [String: ProofTypeSupportedMeta]? = nil,
      display: [Display]? = nil,
      claims: [Claim] = [],
      credentialDefinition: CredentialDefinitionTO
    ) {
      self.format = format
      self.scope = scope
      self.vct = vct
      self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
      self.credentialSigningAlgValuesSupported = credentialSigningAlgValuesSupported
      self.proofTypesSupported = proofTypesSupported
      self.display = display
      self.credentialDefinition = credentialDefinition
      self.claims = claims
    }
    
    func toDomain() throws -> SdJwtVcFormat.CredentialConfiguration {
      
      let bindingMethods = try cryptographicBindingMethodsSupported?.compactMap {
        try CryptographicBindingMethod(method: $0)
      } ?? []
      let display: [Display] = self.display ?? []

      let credentialSigningAlgValuesSupported: [String] = self.credentialSigningAlgValuesSupported ?? []
      let credentialDefinition = self.credentialDefinition.toDomain()
      
      return .init(
        scope: scope, 
        vct: vct,
        cryptographicBindingMethodsSupported: bindingMethods,
        credentialSigningAlgValuesSupported: credentialSigningAlgValuesSupported,
        proofTypesSupported: self.proofTypesSupported,
        display: display,
        credentialDefinition: credentialDefinition,
        claims: claims
      )
    }
  }
  
  struct CredentialConfiguration: Codable, Sendable {
    public let scope: String?
    public let vct: String?
    public let cryptographicBindingMethodsSupported: [CryptographicBindingMethod]
    public let credentialSigningAlgValuesSupported: [String]
    public let proofTypesSupported: [String: ProofTypeSupportedMeta]?
    public let display: [Display]
    public let claims: [Claim]
    public let credentialDefinition: CredentialDefinition
    
    enum CodingKeys: String, CodingKey {
      case scope
      case vct
      case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
      case credentialSigningAlgValuesSupported = "credential_signing_alg_values_supported"
      case proofTypesSupported = "proof_types_supported"
      case display
      case credentialDefinition = "credential_definition"
      case claims
    }
    
    public init(
      scope: String?,
      vct: String?,
      cryptographicBindingMethodsSupported: [CryptographicBindingMethod],
      credentialSigningAlgValuesSupported: [String],
      proofTypesSupported: [String: ProofTypeSupportedMeta]?,
      display: [Display],
      credentialDefinition: CredentialDefinition,
      claims: [Claim]
    ) {
      self.scope = scope
      self.vct = vct
      self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
      self.credentialSigningAlgValuesSupported = credentialSigningAlgValuesSupported
      self.proofTypesSupported = proofTypesSupported
      self.display = display
      self.credentialDefinition = credentialDefinition
      self.claims = claims
    }
    
    public init(from decoder: Decoder) throws {
      let container = try decoder.container(keyedBy: CodingKeys.self)
      scope = try container.decodeIfPresent(String.self, forKey: .scope)
      vct = try container.decodeIfPresent(String.self, forKey: .vct)
      cryptographicBindingMethodsSupported = try container.decode([CryptographicBindingMethod].self, forKey: .cryptographicBindingMethodsSupported)
      credentialSigningAlgValuesSupported = try container.decode([String].self, forKey: .credentialSigningAlgValuesSupported)
      
      let proofTypes = try? container.decode([String: ProofTypeSupportedMeta].self, forKey: .proofTypesSupported)
      proofTypesSupported = proofTypes
      
      display = try container.decode([Display].self, forKey: .display)
      credentialDefinition = try container.decode(CredentialDefinition.self, forKey: .credentialDefinition)
      claims = try container.decode([Claim].self, forKey: .claims)
    }
    
    public func encode(to encoder: Encoder) throws {
      var container = encoder.container(keyedBy: CodingKeys.self)
      try container.encode(scope, forKey: .scope)
      try container.encode(cryptographicBindingMethodsSupported, forKey: .cryptographicBindingMethodsSupported)
      try container.encode(credentialSigningAlgValuesSupported, forKey: .credentialSigningAlgValuesSupported)
      try container.encode(proofTypesSupported, forKey: .proofTypesSupported)
      try container.encode(display, forKey: .display)
      try container.encode(credentialDefinition, forKey: .credentialDefinition)
      try container.encode(claims, forKey: .claims)
    }
    
    init(json: JSON) throws {
      self.scope = json["scope"].string
      self.vct = json["vct"].string
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
      
      self.display = json["display"].arrayValue.map { json in
        Display(json: json)
      }
      
      self.credentialDefinition = try CredentialDefinition(json: json["credential_definition"])
      
      let claims = json["claims"].array?.compactMap({
        try? Claim(json: $0)
      }) ?? []
      self.claims = claims
    }
    
    func toIssuanceRequest(
      responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
      credentialIdentifier: CredentialIdentifier? = nil,
      requestPayload: IssuanceRequestPayload,
      proofs: [Proof]
    ) throws -> CredentialIssuanceRequest {
      try .single(
        .sdJwtVc(
          .init(
            scope: scope,
            proofs: proofs,
            vct: vct,
            credentialEncryptionJwk: responseEncryptionSpec?.jwk,
            credentialEncryptionKey: responseEncryptionSpec?.privateKey,
            credentialResponseEncryptionAlg: responseEncryptionSpec?.algorithm,
            credentialResponseEncryptionMethod: responseEncryptionSpec?.encryptionMethod,
            credentialDefinition: .init(
              type: credentialDefinition.type,
              claims: claims
            ),
            requestPayload: requestPayload,
            display: display
          )
        ), responseEncryptionSpec
      )
    }
  }
  
  struct CredentialDefinition: Codable, Sendable {
    public let type: String
    public let claims: [Claim]
    
    enum CodingKeys: String, CodingKey {
      case type
      case claims
    }
    
    public init(
      type: String,
      claims: [Claim]
    ) {
      self.type = type
      self.claims = claims
    }
    
    public init(json: JSON) throws {
      self.type = json["type"].stringValue
      let claims = try json["claims"].array?.compactMap({ try Claim(json: $0)}) ?? []
      self.claims = claims
    }
  }
}

public extension SdJwtVcFormat {
  
  static func matchSupportedAndToDomain(
    json: JSON,
    metadata: CredentialIssuerMetadata
  ) throws -> CredentialMetadata {
    
    let credentialDefinition = try CredentialDefinitionTO(json: json).toDomain()
    
    if let credentialConfigurationsSupported = metadata.credentialsSupported.first(where: { (credentialId, credential) in
      switch credential {
      case .sdJwtVc(let credentialConfiguration):
        return credentialConfiguration.credentialDefinition.type == credentialDefinition.type
      default: return false
      }
    }) {
      switch credentialConfigurationsSupported.value {
      case .sdJwtVc(let profile):
        return .sdJwtVc(.init(
          type: credentialDefinition.type,
          scope: profile.scope
        )
      )
      default: break
      }
    }
    throw ValidationError.error(reason: "Unable to parse a list of supported credentials for W3CJsonLdSignedJwtProfile")
  }
}
