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

public struct SdJwtVcFormat: FormatProfile {
  
  static let FORMAT = "vc+sd-jwt"
  
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
  
  struct SdJwtVcSingleCredential: Codable {
    public let proof: Proof?
    public let format: String = SdJwtVcFormat.FORMAT
    public let vct: String?
    public let credentialEncryptionJwk: JWK?
    public let credentialEncryptionKey: SecKey?
    public let credentialResponseEncryptionAlg: JWEAlgorithm?
    public let credentialResponseEncryptionMethod: JOSEEncryptionMethod?
    public let credentialDefinition: CredentialDefinition
    public let requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption
    public let credentialIdentifier: CredentialIdentifier?
    
    enum CodingKeys: String, CodingKey {
      case proof
      case credentialEncryptionJwk
      case credentialResponseEncryptionAlg
      case credentialResponseEncryptionMethod
      case credentialDefinition
      case credentialIdentifier
    }
    
    public init(
      proof: Proof?,
      vct: String?,
      credentialEncryptionJwk: JWK? = nil,
      credentialEncryptionKey: SecKey? = nil,
      credentialResponseEncryptionAlg: JWEAlgorithm? = nil,
      credentialResponseEncryptionMethod: JOSEEncryptionMethod? = nil,
      credentialDefinition: CredentialDefinition,
      credentialIdentifier: CredentialIdentifier?
    ) throws {
      self.proof = proof
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
      
      self.requestedCredentialResponseEncryption = try .init(
        encryptionJwk: credentialEncryptionJwk,
        encryptionKey: credentialEncryptionKey,
        responseEncryptionAlg: credentialResponseEncryptionAlg,
        responseEncryptionMethod: credentialResponseEncryptionMethod
      )
    }
    
    public init(from decoder: Decoder) throws {
      fatalError("No supported yet")
    }
    
    public func encode(to encoder: Encoder) throws {
      var container = encoder.container(keyedBy: CodingKeys.self)
      try container.encode(proof, forKey: .proof)
      
      if let credentialEncryptionJwk = credentialEncryptionJwk as? RSAPublicKey {
        try container.encode(credentialEncryptionJwk, forKey: .credentialEncryptionJwk)
      } else if let credentialEncryptionJwk = credentialEncryptionJwk as? ECPublicKey {
        try container.encode(credentialEncryptionJwk, forKey: .credentialEncryptionJwk)
      }
      
      try container.encode(credentialResponseEncryptionAlg, forKey: .credentialResponseEncryptionAlg)
      try container.encode(credentialResponseEncryptionMethod, forKey: .credentialResponseEncryptionMethod)
      
      try container.encode(credentialDefinition, forKey: .credentialDefinition)
    }
    
    public struct CredentialDefinition: Codable {
      public let type: String
      public let claims: ClaimSet?
      
      enum CodingKeys: String, CodingKey {
        case type
        case claims
      }
      
      public init(
        type: String,
        claims: ClaimSet?
      ) {
        self.type = type
        self.claims = claims
      }
    }
  }
  
  struct SdJwtVcClaimSet: Codable {
    public let claims: [ClaimName: Claim]
    
    public init(claims: [ClaimName : Claim]) {
      self.claims = claims
    }
  }
  
  struct CredentialDefinitionTO: Codable {
    public let type: String
    public let claims: [String: Claim]?
    
    enum CodingKeys: String, CodingKey {
      case type = "type"
      case claims = "claims"
    }
    
    public init(type: String, claims: [String : Claim]?) {
      self.type = type
      self.claims = claims
    }
    
    public init(json: JSON) {
      type = json["type"].stringValue
      
      if let credentialSubjectDict = json["claims"].dictionaryObject as? [String: [String: Any]] {
        claims = credentialSubjectDict.compactMapValues { claimDict in
          Claim(json: JSON(claimDict))
        }
      } else {
        claims = nil
      }
    }
    
    func toDomain() -> CredentialDefinition {
      CredentialDefinition(
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
    public let proofTypesSupported: [String: ProofSigningAlgorithmsSupported]?
    public let display: [Display]?
    public let credentialDefinition: CredentialDefinitionTO
    
    enum CodingKeys: String, CodingKey {
      case format
      case scope
      case vct
      case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
      case credentialSigningAlgValuesSupported = "credential_signing_alg_values_supported"
      case proofTypesSupported = "proof_types_supported"
      case display
      case credentialDefinition = "credential_definition"
    }
    
    public init(
      format: String,
      scope: String? = nil,
      vct: String? = nil,
      cryptographicBindingMethodsSupported: [String]? = nil,
      credentialSigningAlgValuesSupported: [String]? = nil,
      proofTypesSupported: [String: ProofSigningAlgorithmsSupported]? = nil,
      display: [Display]? = nil,
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
        credentialDefinition: credentialDefinition
      )
    }
  }
  
  struct CredentialConfiguration: Codable {
    public let scope: String?
    public let vct: String?
    public let cryptographicBindingMethodsSupported: [CryptographicBindingMethod]
    public let credentialSigningAlgValuesSupported: [String]
    public let proofTypesSupported: [String: ProofSigningAlgorithmsSupported]?
    public let display: [Display]
    public let credentialDefinition: CredentialDefinition
    
    enum CodingKeys: String, CodingKey {
      case scope
      case vct
      case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
      case credentialSigningAlgValuesSupported = "credential_signing_alg_values_supported"
      case proofTypesSupported = "proof_types_supported"
      case display
      case credentialDefinition = "credential_definition"
    }
    
    var claimList: [String] {
      return self.credentialDefinition.claims?.keys.map { $0 } ?? []
    }
    
    public init(
      scope: String?,
      vct: String?,
      cryptographicBindingMethodsSupported: [CryptographicBindingMethod],
      credentialSigningAlgValuesSupported: [String],
      proofTypesSupported: [String: ProofSigningAlgorithmsSupported]?,
      display: [Display],
      credentialDefinition: CredentialDefinition
    ) {
      self.scope = scope
      self.vct = vct
      self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
      self.credentialSigningAlgValuesSupported = credentialSigningAlgValuesSupported
      self.proofTypesSupported = proofTypesSupported
      self.display = display
      self.credentialDefinition = credentialDefinition
    }
    
    public init(from decoder: Decoder) throws {
      let container = try decoder.container(keyedBy: CodingKeys.self)
      scope = try container.decodeIfPresent(String.self, forKey: .scope)
      vct = try container.decodeIfPresent(String.self, forKey: .vct)
      cryptographicBindingMethodsSupported = try container.decode([CryptographicBindingMethod].self, forKey: .cryptographicBindingMethodsSupported)
      credentialSigningAlgValuesSupported = try container.decode([String].self, forKey: .credentialSigningAlgValuesSupported)
      
      let proofTypes = try? container.decode([String: ProofSigningAlgorithmsSupported].self, forKey: .proofTypesSupported)
      proofTypesSupported = proofTypes
      
      display = try container.decode([Display].self, forKey: .display)
      credentialDefinition = try container.decode(CredentialDefinition.self, forKey: .credentialDefinition)
    }
    
    public func encode(to encoder: Encoder) throws {
      var container = encoder.container(keyedBy: CodingKeys.self)
      try container.encode(scope, forKey: .scope)
      try container.encode(cryptographicBindingMethodsSupported, forKey: .cryptographicBindingMethodsSupported)
      try container.encode(credentialSigningAlgValuesSupported, forKey: .credentialSigningAlgValuesSupported)
      try container.encode(proofTypesSupported, forKey: .proofTypesSupported)
      try container.encode(display, forKey: .display)
      try container.encode(credentialDefinition, forKey: .credentialDefinition)
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
          return ProofSigningAlgorithmsSupported(algorithms: algorithms)
        }
        return nil
      }
      
      self.display = json["display"].arrayValue.map { json in
        Display(json: json)
      }
      self.credentialDefinition = CredentialDefinition(json: json["credential_definition"])
    }
    
    func toIssuanceRequest(
      responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
      credentialIdentifier: CredentialIdentifier? = nil,
      claimSet: ClaimSet?,
      proof: Proof?
    ) throws -> CredentialIssuanceRequest {
      try .single(
        .sdJwtVc(
          .init(
            proof: proof, 
            vct: vct,
            credentialEncryptionJwk: responseEncryptionSpec?.jwk,
            credentialEncryptionKey: responseEncryptionSpec?.privateKey,
            credentialResponseEncryptionAlg: responseEncryptionSpec?.algorithm,
            credentialResponseEncryptionMethod: responseEncryptionSpec?.encryptionMethod,
            credentialDefinition: .init(
              type: credentialDefinition.type,
              claims: try claimSet?.validate(claims: self.claimList)
            ),
            credentialIdentifier: credentialIdentifier
          )
        ), responseEncryptionSpec
      )
    }
  }
  
  struct CredentialDefinition: Codable {
    public let type: String
    public let claims: [ClaimName: Claim?]?
    
    enum CodingKeys: String, CodingKey {
      case type
      case claims
    }
    
    public init(
      type: String,
      claims: [ClaimName: Claim?]?
    ) {
      self.type = type
      self.claims = claims
    }
    
    public init(json: JSON) {
      self.type = json["type"].stringValue
      
      var claimsDict: [ClaimName: Claim?] = [:]
      let claimsJSON = json["claims"]
      for (key, subJSON): (String, JSON) in claimsJSON.dictionaryValue {
        claimsDict[key] = Claim(json: subJSON)
      }
      self.claims = claimsDict
    }
  }
}

public extension SdJwtVcFormat {
  
  static func matchSupportedAndToDomain(
    json: JSON,
    metadata: CredentialIssuerMetadata
  ) throws -> CredentialMetadata {
    
    let credentialDefinition = CredentialDefinitionTO(json: json).toDomain()
    
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
