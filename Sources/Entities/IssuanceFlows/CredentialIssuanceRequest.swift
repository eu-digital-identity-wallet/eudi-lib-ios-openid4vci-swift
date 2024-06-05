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

public let FORMAT_MSO_MDOC = "mso_mdoc"
public let FORMAT_SD_JWT_VC = "vc+sd-jwt"
public let FORMAT_W3C_JSONLD_DATA_INTEGRITY = "ldp_vc"
public let FORMAT_W3C_JSONLD_SIGNED_JWT = "jwt_vc_json-ld"
public let FORMAT_W3C_SIGNED_JWT = "jwt_vc_json"

public typealias Namespace = String
public typealias ClaimName = String

public typealias MsoMdocClaims = [Namespace: [ClaimName: Claim]]
public extension MsoMdocClaims {
  init(json: JSON) {
    var claims = MsoMdocClaims()
    if let _ = json.dictionaryObject {
      for (namespace, subJSON) in json.dictionaryValue {
        var namespaceClaims = [ClaimName: Claim]()
        for (claimName, claimJSON) in subJSON.dictionaryValue {
          let claim = Claim(
            mandatory: claimJSON["mandatory"].bool,
            valueType: claimJSON["valuetype"].string,
            display: claimJSON["display"].arrayValue.compactMap {
              Display(json: $0)
            }
          )
          namespaceClaims[claimName] = claim
        }
        claims[namespace] = namespaceClaims
      }
    } else if let jsonArray = json.arrayObject {
      for element in jsonArray {
        if let dictionary = element as? [String: String] {
          if let key = dictionary.keys.first, let value = dictionary[key] {
            claims[key] = [value: Claim()]
          }
        }
      }
    }
    self = claims
  }
}

public enum CredentialIssuanceRequest {
  case single(SingleCredential, IssuanceResponseEncryptionSpec?)
  case batch([SingleCredential])
}

public struct DeferredCredentialRequest: Codable {
  let transactionId: String
  let token: IssuanceAccessToken
}

public enum SingleCredential {
  case msoMdoc(MsoMdocFormat.MsoMdocSingleCredential)
  case sdJwtVc(SdJwtVcFormat.SdJwtVcSingleCredential)
}

public extension SingleCredential {
  func toDictionary() throws -> JSON {
    switch self {
    case .msoMdoc(let credential):
      switch credential.requestedCredentialResponseEncryption {
      case .notRequested:
        if let identifier = credential.credentialIdentifier {
          let dictionary = [
            "credential_identifier": identifier,
            "proof": credential.proof != nil ? (try? credential.proof.toDictionary()) : nil
          ] as [String : Any?]
          return JSON(dictionary.filter { $0.value != nil })
          
        } else {
          let dictionary = [
            "format": MsoMdocFormat.FORMAT,
            "doctype": credential.docType,
            "claims": credential.claimSet?.toDictionary(),
            "proof": credential.proof != nil ? (try? credential.proof.toDictionary()) : nil
          ] as [String : Any?]
          return JSON(dictionary.filter { $0.value != nil })
        }
      case .requested(
        let encryptionJwk,
        _,
        let responseEncryptionAlg,
        let responseEncryptionMethod
      ):
        if let identifier = credential.credentialIdentifier {
          let dictionary = [
            "proof": credential.proof != nil ? (try? credential.proof.toDictionary()) : nil,
            "credential_identifier": identifier,
            "credential_response_encryption": [
              "jwk": try encryptionJwk.toDictionary(),
              "alg": responseEncryptionAlg.name,
              "enc": responseEncryptionMethod.name
            ]
          ] as [String : Any?]
          return JSON(dictionary.filter { $0.value != nil })
          
        } else {
          let dictionary = [
            "format": MsoMdocFormat.FORMAT,
            "proof": credential.proof != nil ? (try? credential.proof.toDictionary()) : nil,
            "doctype": credential.docType,
            "credential_response_encryption": [
              "jwk": try encryptionJwk.toDictionary(),
              "alg": responseEncryptionAlg.name,
              "enc": responseEncryptionMethod.name
            ],
            "claims": credential.claimSet?.toDictionary()
          ] as [String : Any?]
          return JSON(dictionary.filter { $0.value != nil })
        }
      }
    case .sdJwtVc(let credential):
      switch credential.requestedCredentialResponseEncryption {
      case .notRequested:
        if let identifier = credential.credentialIdentifier {
          let dictionary = [
            "proof": credential.proof != nil ? (try? credential.proof.toDictionary()) : nil,
            "credential_identifier": identifier
          ] as [String : Any?]
          return JSON(dictionary.filter { $0.value != nil })
          
        } else {
          let dictionary = [
            "vct": credential.vct ?? credential.credentialDefinition.type,
            "proof": credential.proof != nil ? (try? credential.proof.toDictionary()) : nil,
            "format": SdJwtVcFormat.FORMAT,
            "claims": credential.credentialDefinition.claims?.toDictionary()
          ] as [String : Any?]
          return JSON(dictionary.filter { $0.value != nil })
        }
      case .requested(
        let encryptionJwk,
        _,
        let responseEncryptionAlg,
        let responseEncryptionMethod
      ):
        if let identifier = credential.credentialIdentifier {
          let dictionary = [
            "credential_identifier": identifier,
            "proof": credential.proof != nil ? (try? credential.proof.toDictionary()) : nil,
            "credential_response_encryption": [
              "jwk": try encryptionJwk.toDictionary(),
              "alg": responseEncryptionAlg.name,
              "enc": responseEncryptionMethod.name
            ]
          ] as [String : Any?]
          return JSON(dictionary.filter { $0.value != nil })
          
        } else {
          let dictionary = [
            "vct": credential.vct ?? credential.credentialDefinition.type,
            "format": SdJwtVcFormat.FORMAT,
            "proof": credential.proof != nil ? (try? credential.proof.toDictionary()) : nil,
            "credential_response_encryption": [
              "jwk": try encryptionJwk.toDictionary(),
              "alg": responseEncryptionAlg.name,
              "enc": responseEncryptionMethod.name
            ],
            "claims": credential.credentialDefinition.claims?.toDictionary()
          ] as [String : Any?]
          return JSON(dictionary.filter { $0.value != nil })
        }
      }
    }
  }
}

public struct MsoMdocIssuanceRequest {
  public let format: String
  public let proof: ProofType?
  public let credentialEncryptionJwk: JWK?
  public let credentialResponseEncryptionAlg: JWEAlgorithm?
  public let credentialResponseEncryptionMethod: JOSEEncryptionMethod?
  public let doctype: String
  public let claims: [Namespace: [ClaimName: CredentialSupported]]
  
  public init(
    format: String,
    proof: ProofType?,
    credentialEncryptionJwk: JWK?,
    credentialResponseEncryptionAlg: JWEAlgorithm?,
    credentialResponseEncryptionMethod: JOSEEncryptionMethod?,
    doctype: String,
    claims: [Namespace: [ClaimName: CredentialSupported]]
  ) {
    self.format = format
    self.proof = proof
    self.credentialEncryptionJwk = credentialEncryptionJwk
    self.credentialResponseEncryptionAlg = credentialResponseEncryptionAlg
    self.credentialResponseEncryptionMethod = credentialResponseEncryptionMethod
    self.doctype = doctype
    self.claims = claims
  }
  
  static func create(
    proof: ProofType?,
    credentialEncryptionJwk: JWK?,
    credentialResponseEncryptionAlg: JWEAlgorithm?,
    credentialResponseEncryptionMethod: JOSEEncryptionMethod?,
    doctype: String,
    claims: [Namespace: [ClaimName: CredentialSupported]]
  ) -> MsoMdocIssuanceRequest {
    var encryptionMethod = credentialResponseEncryptionMethod
    if credentialResponseEncryptionAlg != nil && credentialResponseEncryptionMethod == nil {
      encryptionMethod = JOSEEncryptionMethod(.A128CBC_HS256)
      
    } else if credentialResponseEncryptionAlg == nil && credentialResponseEncryptionMethod != nil {
      fatalError("Credential response encryption algorithm must be specified if Credential response encryption method is provided")
    }
    
    return MsoMdocIssuanceRequest(
      format: "mso_mdoc",
      proof: proof,
      credentialEncryptionJwk: credentialEncryptionJwk,
      credentialResponseEncryptionAlg: credentialResponseEncryptionAlg,
      credentialResponseEncryptionMethod: encryptionMethod,
      doctype: doctype,
      claims: claims
    )
  }
}

