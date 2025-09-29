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

public struct MsoMdocFormat: FormatProfile {
  static let FORMAT = "mso_mdoc"
  
  public let docType: String
  public let scope: String?
  
  enum CodingKeys: String, CodingKey {
    case docType = "doctype"
    case scope
  }
}

public extension MsoMdocFormat {
  
  struct MsoMdocSingleCredential: Codable, Sendable {
    public let scope: String?
    public let docType: String
    public let proofs: [Proof]
    public let credentialEncryptionJwk: JWK?
    public let credentialEncryptionKey: SecKey?
    public let credentialResponseEncryptionAlg: JWEAlgorithm?
    public let credentialResponseEncryptionMethod: JOSEEncryptionMethod?
    public let credentialIdentifier: CredentialIdentifier?
    public let requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption
    public let requestPayload: IssuanceRequestPayload
    public let display: [Display]
    
    enum CodingKeys: String, CodingKey {
      case scope
      case doctype
      case proof
      case credentialEncryptionJwk
      case credentialResponseEncryptionAlg
      case credentialResponseEncryptionMethod
      case credentialIdentifier
      case requestPayload
      case display
    }
    
    public init(
      scope: String?,
      docType: String,
      proofs: [Proof] = [],
      credentialEncryptionJwk: JWK? = nil,
      credentialEncryptionKey: SecKey? = nil,
      credentialResponseEncryptionAlg: JWEAlgorithm? = nil,
      credentialResponseEncryptionMethod: JOSEEncryptionMethod? = nil,
      credentialIdentifier: CredentialIdentifier? = nil,
      requestPayload: IssuanceRequestPayload,
      display: [Display] = []
    ) throws {
      self.scope = scope
      self.docType = docType
      self.proofs = proofs
      self.credentialEncryptionJwk = credentialEncryptionJwk
      self.credentialEncryptionKey = credentialEncryptionKey
      self.credentialResponseEncryptionAlg = credentialResponseEncryptionAlg
      self.credentialResponseEncryptionMethod = credentialResponseEncryptionMethod
      
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
      try container.encode(credentialIdentifier, forKey: .credentialIdentifier)
      
      switch requestPayload {
      case .identifierBased(_, let credentialIdentifier):
        try container.encode(credentialIdentifier, forKey: .credentialIdentifier)
      case .configurationBased(let credentialConfigurationIdentifier):
        try container.encode(credentialConfigurationIdentifier, forKey: .credentialIdentifier)
      }
    }
  }
  
  struct CredentialConfigurationDTO: Codable {
    public let format: String
    public let scope: String?
    public let cryptographicBindingMethodsSupported: [String]?
    public let credentialSigningAlgValuesSupported: [String]?
    public let proofTypesSupported: [String: ProofTypeSupportedMeta]?
    public let credentialMetadata: ConfigurationCredentialMetadata?
    public let docType: String
    public let policy: Policy?
    
    enum CodingKeys: String, CodingKey {
      case format
      case scope
      case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
      case credentialSigningAlgValuesSupported = "credential_signing_alg_values_supported"
      case proofTypesSupported = "proof_types_supported"
      case credentialMetadata = "credential_metadata"
      case docType = "doctype"
      case policy
    }
    
    public init(
      format: String,
      scope: String? = nil,
      cryptographicBindingMethodsSupported: [String]? = nil,
      credentialSigningAlgValuesSupported: [String]? = nil,
      proofTypesSupported: [String: ProofTypeSupportedMeta]? = nil,
      credentialMetadata: ConfigurationCredentialMetadata? = nil,
      docType: String,
      policy: Policy? = nil
    ) {
      self.format = format
      self.scope = scope
      self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
      self.credentialSigningAlgValuesSupported = credentialSigningAlgValuesSupported
      self.proofTypesSupported = proofTypesSupported
      self.credentialMetadata = credentialMetadata
      self.docType = docType
      self.policy = policy
    }
    
    func toDomain() throws -> MsoMdocFormat.CredentialConfiguration {
      
      let bindingMethods = try cryptographicBindingMethodsSupported?.compactMap {
        try CryptographicBindingMethod(method: $0)
      } ?? []
      
      return .init(
        format: format,
        scope: scope,
        cryptographicBindingMethodsSupported: bindingMethods,
        credentialSigningAlgValuesSupported: credentialSigningAlgValuesSupported ?? [],
        proofTypesSupported: self.proofTypesSupported,
        credentialMetadata: credentialMetadata,
        docType: docType,
        policy: policy
      )
    }
  }
  
  struct CredentialConfiguration: Codable, Sendable {
    public let format: String?
    public let scope: String?
    public let cryptographicBindingMethodsSupported: [CryptographicBindingMethod]
    public let credentialSigningAlgValuesSupported: [String]
    public let proofTypesSupported: [String: ProofTypeSupportedMeta]?
    public let credentialMetadata: ConfigurationCredentialMetadata?
    public let docType: String
    public let policy: Policy?
    
    enum CodingKeys: String, CodingKey {
      case format
      case scope
      case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
      case credentialSigningAlgValuesSupported = "credential_signing_alg_values_supported"
      case proofTypesSupported = "proof_types_supported"
      case credentialMetadata = "credential_metadata"
      case docType = "doctype"
      case policy
    }
    
    public init(
      format: String?,
      scope: String?,
      cryptographicBindingMethodsSupported: [CryptographicBindingMethod],
      credentialSigningAlgValuesSupported: [String],
      proofTypesSupported: [String: ProofTypeSupportedMeta]?,
      credentialMetadata: ConfigurationCredentialMetadata?,
      docType: String,
      policy: Policy?
    ) {
      self.format = format
      self.scope = scope
      self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
      self.credentialSigningAlgValuesSupported = credentialSigningAlgValuesSupported
      self.proofTypesSupported = proofTypesSupported
      self.credentialMetadata = credentialMetadata
      self.docType = docType
      self.policy = policy
    }
    
    public init(from decoder: Decoder) throws {
      let container = try decoder.container(keyedBy: CodingKeys.self)
      
      format = try container.decodeIfPresent(String.self, forKey: .format)
      scope = try container.decodeIfPresent(String.self, forKey: .scope)
      cryptographicBindingMethodsSupported = try container.decode([CryptographicBindingMethod].self, forKey: .cryptographicBindingMethodsSupported)
      credentialSigningAlgValuesSupported = try container.decode([String].self, forKey: .credentialSigningAlgValuesSupported)
      
      let proofTypes = try? container.decode([String: ProofTypeSupportedMeta].self, forKey: .proofTypesSupported)
      proofTypesSupported = proofTypes
      
      credentialMetadata = try container.decode(ConfigurationCredentialMetadata.self, forKey: .credentialMetadata)
      docType = try container.decode(String.self, forKey: .docType)
      policy = try? container.decode(Policy.self, forKey: .policy)
    }
    
    public func encode(to encoder: Encoder) throws {
      var container = encoder.container(keyedBy: CodingKeys.self)
      
      try container.encode(format, forKey: .format)
      try container.encode(scope, forKey: .scope)
      try container.encode(cryptographicBindingMethodsSupported, forKey: .cryptographicBindingMethodsSupported)
      try container.encode(credentialSigningAlgValuesSupported, forKey: .credentialSigningAlgValuesSupported)
      try container.encode(proofTypesSupported, forKey: .proofTypesSupported)
      try container.encode(credentialMetadata, forKey: .credentialMetadata)
      try container.encode(docType, forKey: .docType)
      try container.encode(policy, forKey: .policy)
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
          let requirement = types["key_attestations_required"]
          return .init(
            algorithms: algorithms,
            keyAttestationRequirement: try? .init(json: JSON(requirement ?? [:]))
          )
        }
        return nil
      }
      
      self.credentialMetadata = try ConfigurationCredentialMetadata(json: json["credential_metadata"])
      self.docType = json["doctype"].stringValue
      self.policy = .init(json: json["policy"])
    }
    
    func toIssuanceRequest(
      responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
      credentialIdentifier: CredentialIdentifier? = nil,
      requestPayload: IssuanceRequestPayload,
      proofs: [Proof]
    ) throws -> CredentialIssuanceRequest {
      try .single(
        .msoMdoc(
          .init(
            scope: scope,
            docType: docType,
            proofs: proofs,
            credentialEncryptionJwk: responseEncryptionSpec?.jwk,
            credentialEncryptionKey: responseEncryptionSpec?.privateKey,
            credentialResponseEncryptionAlg: responseEncryptionSpec?.algorithm,
            credentialResponseEncryptionMethod: responseEncryptionSpec?.encryptionMethod,
            requestPayload: requestPayload,
            display: credentialMetadata?.display ?? []
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
    
    if let credentialConfigurationsSupported = metadata.credentialsSupported.first(where: { (_, credential) in
      switch credential {
      case .msoMdoc(let credentialConfiguration):
        return credentialConfiguration.docType == docType
      default: return false
      }
    }) {
      switch credentialConfigurationsSupported.value {
      case .msoMdoc(let profile):
        
        // Validation: proof_types_supported must be present if cryptographic_binding_methods_supported is present
        if !profile.cryptographicBindingMethodsSupported.isEmpty {
          guard let proofTypes = profile.proofTypesSupported, !proofTypes.isEmpty else {
            throw ValidationError.error(reason: "Property `proof_types_supported` must be present if `cryptographic_binding_methods_supported` is present")
          }
        }
        
        return .msoMdoc(.init(docType: docType, scope: profile.scope))
      default: break
      }
    }
    
    throw ValidationError.error(reason: "Unable to parse a list of supported credentials for MsoMdocProfile")
  }
}
