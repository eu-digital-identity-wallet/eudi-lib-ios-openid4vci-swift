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
import JOSESwift
import SwiftyJSON

public enum CredentialSupported: Codable, Sendable {
  case scope(Scope)
  case msoMdoc(MsoMdocFormat.CredentialConfiguration)
  case w3CSignedJwt(W3CSignedJwtFormat.CredentialConfiguration)
  case w3CJsonLdSignedJwt(W3CJsonLdSignedJwtFormat.CredentialConfiguration)
  case w3CJsonLdDataIntegrity(W3CJsonLdDataIntegrityFormat.CredentialConfiguration)
  case sdJwtVc(SdJwtVcFormat.CredentialConfiguration)
}

public extension CredentialSupported {
  
  internal func supportsProofTypes() -> Bool {
    switch self {
    case .scope:
      return false
    case .msoMdoc(let configuration):
      return configuration.proofTypesSupported?.isEmpty == false
    case .w3CSignedJwt(let configuration):
      return configuration.proofTypesSupported?.isEmpty == false
    case .w3CJsonLdSignedJwt:
      return false
    case .w3CJsonLdDataIntegrity:
      return false
    case .sdJwtVc(let configuration):
      return configuration.proofTypesSupported?.isEmpty == false
    }
  }
  
  func getScope() -> String? {
    switch self {
    case .scope(let scope):
      return scope.value
    case .msoMdoc(let credential):
      return credential.scope
    case .w3CSignedJwt(let credential):
      return credential.scope
    case .w3CJsonLdSignedJwt(let credential):
      return credential.scope
    case .w3CJsonLdDataIntegrity(let credential):
      return credential.scope
    case .sdJwtVc(let credential):
      return credential.scope
    }
  }
  
  func toIssuanceRequest(
    requester: IssuanceRequesterType,
    proofs: [Proof] = [],
    issuancePayload: IssuanceRequestPayload,
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) throws -> CredentialIssuanceRequest {
    
    let (issuerEncryption, responseEncryptionSpec) = try validateAndPrepareEncryption(
      requester: requester,
      responseEncryptionSpecProvider: responseEncryptionSpecProvider
    )
    
    switch self {
    case .msoMdoc(let credentialConfiguration):
      return try credentialConfiguration.toIssuanceRequest(
        responseEncryptionSpec: issuerEncryption.notSupported ? nil : responseEncryptionSpec,
        requestPayload: issuancePayload,
        proofs: proofs
      )

    case .sdJwtVc(let credentialConfiguration):
      return try credentialConfiguration.toIssuanceRequest(
        responseEncryptionSpec: issuerEncryption.notSupported ? nil : responseEncryptionSpec,
        requestPayload: issuancePayload,
        proofs: proofs
      )
    default:
      throw ValidationError.error(
        reason: "Unsupported profile for issuance request"
      )
    }
  }
  
  private func validateAndPrepareEncryption(
    requester: IssuanceRequesterType,
    responseEncryptionSpecProvider: (CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) throws -> (CredentialResponseEncryption, IssuanceResponseEncryptionSpec?) {
    let issuerEncryption = requester.issuerMetadata.credentialResponseEncryption
    let responseEncryptionSpec = responseEncryptionSpecProvider(issuerEncryption)
    
    if let responseEncryptionSpec {
      switch issuerEncryption {
      case .notSupported:
        break
        
      case .required(
        let algorithmsSupported,
        let encryptionMethodsSupported,
        let compressionMethodsSupported
      ), .notRequired(
        let algorithmsSupported,
        let encryptionMethodsSupported,
        let compressionMethodsSupported
      ):
        if !algorithmsSupported.contains(responseEncryptionSpec.algorithm) {
          throw CredentialIssuanceError.responseEncryptionAlgorithmNotSupportedByIssuer
        }
        
        if !encryptionMethodsSupported.contains(responseEncryptionSpec.encryptionMethod) {
          throw CredentialIssuanceError.responseEncryptionMethodNotSupportedByIssuer
        }
        
        if let compressionMethodsSupported,
           let compressionMethod = responseEncryptionSpec.compressionMethod,
           !compressionMethodsSupported.contains(compressionMethod) {
          throw CredentialIssuanceError.responseCompressionMethodNotSupportedByIssuer
        }
      }
    }
    return (issuerEncryption, responseEncryptionSpec)
  }
  
  var proofTypesSupported: [String: ProofTypeSupportedMeta]? {
    switch self {
    case .msoMdoc(let spec):
      spec.proofTypesSupported
    case .sdJwtVc(let spec):
      spec.proofTypesSupported
    default:
      nil
    }
  }
  
  func proofTypes(type: ProofType) -> [SignatureAlgorithm] {
    switch self {
    case .msoMdoc(let spec):
      spec.proofTypesSupported?[type.rawValue].map { meta in
        meta.algorithms.compactMap { algorithm in
          SignatureAlgorithm(rawValue: algorithm)
        }
      } ?? []
    case .sdJwtVc(let spec):
      spec.proofTypesSupported?[type.rawValue].map { meta in
        meta.algorithms.compactMap { algorithm in
          SignatureAlgorithm(rawValue: algorithm)
        }
      } ?? []
    default:
      []
    }
  }
}


public struct ConfigurationCredentialMetadata: Codable, Sendable {
  public let display: [Display]
  public let claims: [Claim]
  
  enum CodingKeys: String, CodingKey {
    case display
    case claims
  }
  
  public init(display: [Display], claims: [Claim]) {
    self.display = display
    self.claims = claims
  }
  
  public init(json: JSON) throws {
    self.display = json["display"].arrayValue.map { json in
      Display(json: json)
    }
    let claims = try json["claims"].array?.compactMap({ try Claim(json: $0)}) ?? []
    self.claims = claims
  }
}
