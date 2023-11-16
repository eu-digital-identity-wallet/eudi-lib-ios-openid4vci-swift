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

public struct SdJwtVcProfile: Profile {
  
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

public extension SdJwtVcProfile {
  
  struct SdJwtVcSingleCredential: Codable {
    public let proof: Proof?
    public let credentialEncryptionJwk: JWK?
    public let credentialResponseEncryptionAlg: JWEAlgorithm?
    public let credentialResponseEncryptionMethod: JOSEEncryptionMethod?
    public let credentialDefinition: CredentialDefinition
    
    enum CodingKeys: String, CodingKey {
      case proof
      case credentialEncryptionJwk
      case credentialResponseEncryptionAlg
      case credentialResponseEncryptionMethod
      case credentialDefinition
    }
    
    public init(
      proof: Proof?,
      type: String,
      credentialEncryptionJwk: JWK? = nil,
      credentialResponseEncryptionAlg: JWEAlgorithm? = nil,
      credentialResponseEncryptionMethod: JOSEEncryptionMethod? = nil,
      credentialDefinition: CredentialDefinition
    ) {
      self.proof = proof
      self.credentialEncryptionJwk = credentialEncryptionJwk
      self.credentialResponseEncryptionAlg = credentialResponseEncryptionAlg
      self.credentialResponseEncryptionMethod = credentialResponseEncryptionMethod
      self.credentialDefinition = .init(
        type: type,
        claims: credentialDefinition.claims
      )
    }
    
    public func requiresEncryptedResponse() -> Bool {
      credentialResponseEncryptionAlg != nil &&
      credentialEncryptionJwk != nil &&
      credentialResponseEncryptionMethod != nil
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
  
  struct CredentialSupportedDTO: Codable {
    public let format: String
    public let scope: String?
    public let cryptographicBindingMethodsSupported: [String]?
    public let cryptographicSuitesSupported: [String]?
    public let proofTypesSupported: [String]?
    public let display: [Display]?
    public let credentialDefinition: CredentialDefinitionTO
    
    enum CodingKeys: String, CodingKey {
      case format
      case scope
      case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
      case cryptographicSuitesSupported = "cryptographic_suites_supported"
      case proofTypesSupported = "proof_types_supported"
      case display
      case credentialDefinition = "credential_definition"
    }
    
    public init(
      format: String,
      scope: String? = nil,
      cryptographicBindingMethodsSupported: [String]? = nil,
      cryptographicSuitesSupported: [String]? = nil,
      proofTypesSupported: [String]? = nil,
      display: [Display]? = nil,
      credentialDefinition: CredentialDefinitionTO
    ) {
      self.format = format
      self.scope = scope
      self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
      self.cryptographicSuitesSupported = cryptographicSuitesSupported
      self.proofTypesSupported = proofTypesSupported
      self.display = display
      self.credentialDefinition = credentialDefinition
    }
    
    func toDomain() throws -> SdJwtVcProfile.CredentialSupported {
      
      let bindingMethods = try cryptographicBindingMethodsSupported?.compactMap {
        try CryptographicBindingMethod(method: $0)
      } ?? []
      let display: [Display] = self.display ?? []
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
        credentialDefinition: credentialDefinition
      )
    }
  }
  
  struct CredentialSupported: Codable {
    public let scope: String?
    public let cryptographicBindingMethodsSupported: [CryptographicBindingMethod]
    public let cryptographicSuitesSupported: [String]
    public let proofTypesSupported: [ProofType]?
    public let display: [Display]
    public let credentialDefinition: CredentialDefinition
    
    enum CodingKeys: String, CodingKey {
      case scope
      case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
      case cryptographicSuitesSupported = "cryptographic_suites_supported"
      case proofTypesSupported = "proof_types_supported"
      case display
      case credentialDefinition = "credential_definition"
    }
    
    public init(
      scope: String?,
      cryptographicBindingMethodsSupported: [CryptographicBindingMethod],
      cryptographicSuitesSupported: [String],
      proofTypesSupported: [ProofType]?,
      display: [Display],
      credentialDefinition: CredentialDefinition
    ) {
      self.scope = scope
      self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
      self.cryptographicSuitesSupported = cryptographicSuitesSupported
      self.proofTypesSupported = proofTypesSupported
      self.display = display
      self.credentialDefinition = credentialDefinition
    }
    
    public init(from decoder: Decoder) throws {
      let container = try decoder.container(keyedBy: CodingKeys.self)
      
      scope = try container.decodeIfPresent(String.self, forKey: .scope)
      cryptographicBindingMethodsSupported = try container.decode([CryptographicBindingMethod].self, forKey: .cryptographicBindingMethodsSupported)
      cryptographicSuitesSupported = try container.decode([String].self, forKey: .cryptographicSuitesSupported)
      proofTypesSupported = try? container.decode([ProofType].self, forKey: .proofTypesSupported)
      display = try container.decode([Display].self, forKey: .display)
      credentialDefinition = try container.decode(CredentialDefinition.self, forKey: .credentialDefinition)
    }
    
    public func encode(to encoder: Encoder) throws {
      var container = encoder.container(keyedBy: CodingKeys.self)
      
      try container.encode(scope, forKey: .scope)
      try container.encode(cryptographicBindingMethodsSupported, forKey: .cryptographicBindingMethodsSupported)
      try container.encode(cryptographicSuitesSupported, forKey: .cryptographicSuitesSupported)
      try container.encode(proofTypesSupported, forKey: .proofTypesSupported)
      try container.encode(display, forKey: .display)
      try container.encode(credentialDefinition, forKey: .credentialDefinition)
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
      self.credentialDefinition = CredentialDefinition(json: json["credential_definition"])
    }
    
    func toIssuanceRequest(
      claimSet: ClaimSet?,
      proof: Proof?
    ) throws -> CredentialIssuanceRequest {
      
      func validateClaimSet(
        claimSet: SdJwtVcClaimSet
      ) throws -> SdJwtVcClaimSet {
        if credentialDefinition.claims == nil ||
           (((credentialDefinition.claims?.isEmpty) != nil) && claimSet.claims.isEmpty) {
          throw CredentialIssuanceError.invalidIssuanceRequest(
            "Issuer does not support claims for credential [\(SdJwtVcProfile.FORMAT)-\(credentialDefinition.type)]"
          )
        }
        
        if credentialDefinition.claims == nil || (((credentialDefinition.claims?.isEmpty) != nil) && claimSet.claims.isEmpty) {
          throw CredentialIssuanceError.invalidIssuanceRequest(
            "Issuer does not support claims for credential [\(SdJwtVcProfile.FORMAT)-\(credentialDefinition.type)]"
          )
        }
        return claimSet
      }
      
      let validClaimSet: SdJwtVcProfile.SdJwtVcClaimSet?
      if let claimSet = claimSet {
        switch claimSet {
        case .sdJwtVc(let claimSet):
          validClaimSet = try validateClaimSet(claimSet: claimSet)
        default: throw CredentialIssuanceError.invalidIssuanceRequest(
          "Invalid Claim Set provided for issuance"
        )
        }
      }
      
      return .single(.sdJwtVc(.init(
        proof: proof, 
        type: credentialDefinition.type,
        credentialDefinition: credentialDefinition
      )))
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

public extension SdJwtVcProfile {
  
  static func matchSupportedAndToDomain(
    json: JSON,
    metadata: CredentialIssuerMetadata
  ) throws -> CredentialMetadata {
    
    let credentialDefinition = CredentialDefinitionTO(json: json).toDomain()
    
    if let credentialsSupported = metadata.credentialsSupported.first(where: { credential in
      switch credential {
      case .sdJwtVc(let credentialSupported):
        return credentialSupported.credentialDefinition.type == credentialDefinition.type
      default: return false
      }
    }) {
      switch credentialsSupported {
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
