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

public struct MsoMdocFormat: FormatProfile {
  static let FORMAT = "mso_mdoc"
  
  public let docType: String
  public let scope: String?
  
  enum CodingKeys: String, CodingKey {
    case docType = "doctype"
    case scope
  }
  
  init(docType: String, scope: String?) {
    self.docType = docType
    self.scope = scope
  }
}

public extension MsoMdocFormat {
  
  struct MsoMdocSingleCredential: Codable {
    public let docType: String
    public let proof: Proof?
    public let credentialEncryptionJwk: JWK?
    public let credentialEncryptionKey: SecKey?
    public let credentialResponseEncryptionAlg: JWEAlgorithm?
    public let credentialResponseEncryptionMethod: JOSEEncryptionMethod?
    public let claimSet: ClaimSet?
    public let credentialIdentifier: CredentialIdentifier?
    public let requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption
    
    enum CodingKeys: String, CodingKey {
      case doctype
      case proof
      case credentialEncryptionJwk
      case credentialResponseEncryptionAlg
      case credentialResponseEncryptionMethod
      case claimSet
      case credentialIdentifier
    }
    
    public init(
      docType: String,
      proof: Proof? = nil,
      credentialEncryptionJwk: JWK? = nil,
      credentialEncryptionKey: SecKey? = nil,
      credentialResponseEncryptionAlg: JWEAlgorithm? = nil,
      credentialResponseEncryptionMethod: JOSEEncryptionMethod? = nil,
      claimSet: ClaimSet? = nil,
      credentialIdentifier: CredentialIdentifier?
    ) throws {
      self.docType = docType
      self.proof = proof
      self.credentialEncryptionJwk = credentialEncryptionJwk
      self.credentialEncryptionKey = credentialEncryptionKey
      self.credentialResponseEncryptionAlg = credentialResponseEncryptionAlg
      self.credentialResponseEncryptionMethod = credentialResponseEncryptionMethod
      self.claimSet = claimSet
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
      try container.encode(claimSet, forKey: .claimSet)
      try container.encode(credentialIdentifier, forKey: .credentialIdentifier)
    }
  }
  
  struct MsoMdocClaimSet: Codable {
    public let claims: [(Namespace, ClaimName)]
    
    public init(claims: [(Namespace, ClaimName)]) {
      self.claims = claims
    }
    
    public func encode(to encoder: Encoder) throws {
      var container = encoder.unkeyedContainer()
      for (namespace, claimName) in claims {
        var nestedContainer = container.nestedContainer(keyedBy: CodingKeys.self)
        try nestedContainer.encode(namespace, forKey: .namespace)
        try nestedContainer.encode(claimName, forKey: .claimName)
      }
    }
    
    public init(from decoder: Decoder) throws {
      var container = try decoder.unkeyedContainer()
      var decodedClaims: [(Namespace, ClaimName)] = []
      while !container.isAtEnd {
        let nestedContainer = try container.nestedContainer(keyedBy: CodingKeys.self)
        let namespace = try nestedContainer.decode(Namespace.self, forKey: .namespace)
        let claimName = try nestedContainer.decode(ClaimName.self, forKey: .claimName)
        decodedClaims.append((namespace, claimName))
      }
      claims = decodedClaims
    }
    
    private enum CodingKeys: String, CodingKey {
      case namespace
      case claimName
    }
  }
  
  struct CredentialConfigurationDTO: Codable {
    public let format: String
    public let scope: String?
    public let cryptographicBindingMethodsSupported: [String]?
    public let credentialSigningAlgValuesSupported: [String]?
    public let proofTypesSupported: [String: ProofSigningAlgorithmsSupported]?
    public let display: [Display]?
    public let docType: String
    public let claims: [String: [String: Claim]]?
    public let order: [String]?
    
    enum CodingKeys: String, CodingKey {
      case format
      case scope
      case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
      case credentialSigningAlgValuesSupported = "credential_signing_alg_values_supported"
      case proofTypesSupported = "proof_types_supported"
      case display
      case docType = "doctype"
      case claims
      case order
    }
    
    public init(
      format: String,
      scope: String? = nil,
      cryptographicBindingMethodsSupported: [String]? = nil,
      credentialSigningAlgValuesSupported: [String]? = nil,
      proofTypesSupported: [String: ProofSigningAlgorithmsSupported]? = nil,
      display: [Display]? = nil,
      docType: String,
      claims: [String : [String : Claim]]? = nil,
      order: [String]? = nil
    ) {
      self.format = format
      self.scope = scope
      self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
      self.credentialSigningAlgValuesSupported = credentialSigningAlgValuesSupported
      self.proofTypesSupported = proofTypesSupported
      self.display = display
      self.docType = docType
      self.claims = claims
      self.order = order
    }
    
    func toDomain() throws -> MsoMdocFormat.CredentialConfiguration {
      
      let bindingMethods = try cryptographicBindingMethodsSupported?.compactMap {
        try CryptographicBindingMethod(method: $0)
      } ?? []
      let display: [Display] = self.display ?? []
      
      let credentialSigningAlgValuesSupported: [String] = self.credentialSigningAlgValuesSupported ?? []
      let claims: MsoMdocClaims = claims?.mapValues { namespaceAndClaims in
        namespaceAndClaims.mapValues { claim in
          Claim(
            mandatory: claim.mandatory ?? false,
            valueType: claim.valueType,
            display: claim.display?.compactMap {
              Display(
                name: $0.name,
                locale: $0.locale
              )
            }
          )
        }
      } ?? [:]
      
      return .init(
        format: format,
        scope: scope,
        cryptographicBindingMethodsSupported: bindingMethods,
        credentialSigningAlgValuesSupported: credentialSigningAlgValuesSupported,
        proofTypesSupported: self.proofTypesSupported,
        display: display,
        docType: docType,
        claims: claims,
        order: order ?? []
      )
    }
  }
  
  struct CredentialConfiguration: Codable {
    public let format: String?
    public let scope: String?
    public let cryptographicBindingMethodsSupported: [CryptographicBindingMethod]
    public let credentialSigningAlgValuesSupported: [String]
    public let proofTypesSupported: [String: ProofSigningAlgorithmsSupported]?
    public let display: [Display]
    public let docType: String
    public let claims: MsoMdocClaims
    public let order: [ClaimName]
    
    var claimList: [String] {
      claims.values.flatMap { $0 }.map { $0.0 }
    }
    
    enum CodingKeys: String, CodingKey {
      case format
      case scope
      case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
      case credentialSigningAlgValuesSupported = "credential_signing_alg_values_supported"
      case proofTypesSupported = "proof_types_supported"
      case display
      case docType = "doctype"
      case claims
      case order
    }
    
    public init(
      format: String?,
      scope: String?,
      cryptographicBindingMethodsSupported: [CryptographicBindingMethod],
      credentialSigningAlgValuesSupported: [String],
      proofTypesSupported: [String: ProofSigningAlgorithmsSupported]?,
      display: [Display],
      docType: String,
      claims: MsoMdocClaims,
      order: [ClaimName]
    ) {
      self.format = format
      self.scope = scope
      self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
      self.credentialSigningAlgValuesSupported = credentialSigningAlgValuesSupported
      self.proofTypesSupported = proofTypesSupported
      self.display = display
      self.docType = docType
      self.claims = claims
      self.order = order
    }
    
    public init(from decoder: Decoder) throws {
      let container = try decoder.container(keyedBy: CodingKeys.self)
      
      format = try container.decodeIfPresent(String.self, forKey: .format)
      scope = try container.decodeIfPresent(String.self, forKey: .scope)
      cryptographicBindingMethodsSupported = try container.decode([CryptographicBindingMethod].self, forKey: .cryptographicBindingMethodsSupported)
      credentialSigningAlgValuesSupported = try container.decode([String].self, forKey: .credentialSigningAlgValuesSupported)
      
      let proofTypes = try? container.decode([String: ProofSigningAlgorithmsSupported].self, forKey: .proofTypesSupported)
      proofTypesSupported = proofTypes
      
      display = try container.decode([Display].self, forKey: .display)
      docType = try container.decode(String.self, forKey: .docType)
      claims = try container.decode(MsoMdocClaims.self, forKey: .claims)
      order = try container.decode([ClaimName].self, forKey: .order)
    }
    
    public func encode(to encoder: Encoder) throws {
      var container = encoder.container(keyedBy: CodingKeys.self)
      
      try container.encode(format, forKey: .format)
      try container.encode(scope, forKey: .scope)
      try container.encode(cryptographicBindingMethodsSupported, forKey: .cryptographicBindingMethodsSupported)
      try container.encode(credentialSigningAlgValuesSupported, forKey: .credentialSigningAlgValuesSupported)
      try container.encode(proofTypesSupported, forKey: .proofTypesSupported)
      try container.encode(display, forKey: .display)
      try container.encode(docType, forKey: .docType)
      try container.encode(claims, forKey: .claims)
      try container.encode(order, forKey: .order)
    }
    
    init(json: JSON) throws {
      self.format = json["format"].string
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
      self.docType = json["doctype"].stringValue
      self.claims = MsoMdocClaims(json: json["claims"])
      self.order = json["order"].arrayValue.map {
        ClaimName($0.stringValue)
      }
    }
    
    func toIssuanceRequest(
      responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
      credentialIdentifier: CredentialIdentifier? = nil,
      claimSet: ClaimSet?,
      proof: Proof?
    ) throws -> CredentialIssuanceRequest {
      try .single(
        .msoMdoc(
          .init(
            docType: docType,
            proof: proof,
            credentialEncryptionJwk: responseEncryptionSpec?.jwk,
            credentialEncryptionKey: responseEncryptionSpec?.privateKey,
            credentialResponseEncryptionAlg: responseEncryptionSpec?.algorithm,
            credentialResponseEncryptionMethod: responseEncryptionSpec?.encryptionMethod,
            claimSet: try claimSet?.validate(claims: self.claimList), 
            credentialIdentifier: credentialIdentifier
          )
        ), responseEncryptionSpec
      )
    }
  }
}

public extension MsoMdocFormat {
  
  static func matchSupportedAndToDomain(
    json: JSON,
    metadata: CredentialIssuerMetadata
  ) throws -> CredentialMetadata {
    guard let docType = json["doctype"].string else {
      throw ValidationError.error(reason: "Missing doctype")
    }
    
    if let credentialConfigurationsSupported = metadata.credentialsSupported.first(where: { (credentialId, credential) in
      switch credential {
      case .msoMdoc(let credentialConfiguration):
        return credentialConfiguration.docType == docType
      default: return false
      }
    }) {
      switch credentialConfigurationsSupported.value {
      case .msoMdoc(let profile):
        return .msoMdoc(.init(docType: docType, scope: profile.scope))
      default: break
      }
    }
    
    throw ValidationError.error(reason: "Unable to parse a list of supported credentials for MsoMdocProfile")
  }
}
