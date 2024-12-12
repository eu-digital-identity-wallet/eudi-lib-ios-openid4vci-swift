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

public typealias SdJwtVCMetadataClaims = [ClaimName: Claim]
public extension SdJwtVCMetadataClaims {
  init(json: JSON) {
    var claims = SdJwtVCMetadataClaims()
    if let _ = json.dictionaryObject {
      var namespaceClaims = [ClaimName: Claim]()
      for (claimName, claimJSON) in json.dictionaryValue {
        let claim = Claim(
          mandatory: claimJSON["mandatory"].bool,
          valueType: claimJSON["valuetype"].string,
          display: claimJSON["display"].arrayValue.compactMap {
            Display(json: $0)
          }
        )
        namespaceClaims[claimName] = claim
      }
      claims = namespaceClaims
    } else if let jsonArray = json.arrayObject {
      for element in jsonArray {
        if let dictionary = element as? [String: String] {
          if let key = dictionary.keys.first {
            claims[key] = Claim()
          }
        }
      }
    }
    self = claims
  }
}

public enum CredentialIssuanceRequest {
  case single(SingleCredential, IssuanceResponseEncryptionSpec?)
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
      let proofOrProofs = credential.proofs.proofOrProofs()
      switch credential.requestedCredentialResponseEncryption {
      case .notRequested:
        if let identifier = credential.credentialIdentifier {
          return try JSON.createFrom(
            proofOrProofs: proofOrProofs,
            dictionary: [
              "credential_identifier": identifier
            ]
          )
        } else {
          return try JSON.createFrom(
            proofOrProofs: proofOrProofs,
            dictionary: [
              "format": MsoMdocFormat.FORMAT,
              "doctype": credential.docType,
              "claims": credential.claimSet?.toDictionary()
            ]
          )
        }
      case .requested(
        let encryptionJwk,
        _,
        let responseEncryptionAlg,
        let responseEncryptionMethod
      ):
        if let identifier = credential.credentialIdentifier {
          return try JSON.createFrom(
            proofOrProofs: proofOrProofs,
            dictionary: [
              "credential_identifier": identifier,
              "credential_response_encryption": [
                "jwk": try encryptionJwk.toDictionary(),
                "alg": responseEncryptionAlg.name,
                "enc": responseEncryptionMethod.name
              ]
            ]
          )
          
        } else {
          return try JSON.createFrom(
            proofOrProofs: proofOrProofs,
            dictionary: [
              "format": MsoMdocFormat.FORMAT,
              "doctype": credential.docType,
              "credential_response_encryption": [
                "jwk": try encryptionJwk.toDictionary(),
                "alg": responseEncryptionAlg.name,
                "enc": responseEncryptionMethod.name
              ],
              "claims": credential.claimSet?.toDictionary()
            ]
          )
        }
      }
    case .sdJwtVc(let credential):
      let proofOrProofs = credential.proofs.proofOrProofs()
      switch credential.requestedCredentialResponseEncryption {
      case .notRequested:
        if let identifier = credential.credentialIdentifier {
          return try JSON.createFrom(
            proofOrProofs: proofOrProofs,
            dictionary: [
              "credential_identifier": identifier
            ]
          )
          
        } else {
          return try JSON.createFrom(
            proofOrProofs: proofOrProofs,
            dictionary: [
              "vct": credential.vct ?? credential.credentialDefinition.type,
              "format": SdJwtVcFormat.FORMAT,
              "claims": credential.credentialDefinition.claims?.toDictionary()
            ]
          )
        }
      case .requested(
        let encryptionJwk,
        _,
        let responseEncryptionAlg,
        let responseEncryptionMethod
      ):
        if let identifier = credential.credentialIdentifier {
          return try JSON.createFrom(
            proofOrProofs: proofOrProofs,
            dictionary: [
              "credential_identifier": identifier,
              "credential_response_encryption": [
                "jwk": try encryptionJwk.toDictionary(),
                "alg": responseEncryptionAlg.name,
                "enc": responseEncryptionMethod.name
              ]
            ]
          )
          
        } else {
          return try JSON.createFrom(
            proofOrProofs: proofOrProofs,
            dictionary: [
              "vct": credential.vct ?? credential.credentialDefinition.type,
              "format": SdJwtVcFormat.FORMAT,
              "credential_response_encryption": [
                "jwk": try encryptionJwk.toDictionary(),
                "alg": responseEncryptionAlg.name,
                "enc": responseEncryptionMethod.name
              ],
              "claims": credential.credentialDefinition.claims?.toDictionary()
            ]
          )
        }
      }
    }
  }
}

private extension Array where Element == Proof {
  func proofOrProofs() -> (Proof?, ProofsTO?) {
    if self.isEmpty {
      return (nil, nil)
      
    } else if self.count == 1 {
      return (self.first, nil)
      
    } else {
      let jwtProofs = self.compactMap { proof in
        switch proof {
        case .jwt(let jwt):
          return jwt
        }
      }
      let proofsTO = ProofsTO(jwtProofs: jwtProofs)
      return (nil, proofsTO)
    }
  }
}

private extension JSON {
  static func toJSON(_ tuple: (Proof?, ProofsTO?)) -> JSON? {
    if let proof = tuple.0 {
      return try? .init(["proof": proof.toDictionary()])
    } else if let proofs = tuple.1 {
      return try? .init(["proofs": proofs.toDictionary()])
    } else {
      return nil
    }
  }
  
  static func createFrom(proofOrProofs: (Proof?, ProofsTO?), dictionary: [String: Any?]) throws -> JSON {
    var json = Self.toJSON(proofOrProofs)
    try json?.merge(with: JSON(
      dictionary.compactMapValues { $0 }
    ))
    return json ?? JSON([:])
  }
}
