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

public typealias Namespace = String
public typealias ClaimName = String

public typealias MsoMdocClaims = [Namespace: [ClaimName: Claim]]
public extension MsoMdocClaims {
  init(json: JSON) {
    var claims = MsoMdocClaims()
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
    self = claims
  }
}

public enum CredentialIssuanceRequest {
  case single(SingleCredential)
  case batch([SingleCredential])
}

public struct DeferredCredentialRequest: Codable {
  let transactionId: String
  let token: IssuanceAccessToken
}

public struct SingleCredential: Codable {
  public var format: String
  public var proof: ProofType?
  public var credentialEncryptionJwk: JWK?
  public var credentialResponseEncryptionAlg: JWEAlgorithm?
  public var credentialResponseEncryptionMethod: JOSEEncryptionMethod?
  
  enum CodingKeys: String, CodingKey {
    case format
    case proof
    case credentialEncryptionJwk
    case credentialResponseEncryptionAlg
    case credentialResponseEncryptionMethod
  }
  
  public init(
    format: String,
    proof: ProofType? = nil,
    credentialEncryptionJwk: JWK? = nil,
    credentialResponseEncryptionAlg: JWEAlgorithm? = nil,
    credentialResponseEncryptionMethod: JOSEEncryptionMethod? = nil
  ) {
    self.format = format
    self.proof = proof
    self.credentialEncryptionJwk = credentialEncryptionJwk
    self.credentialResponseEncryptionAlg = credentialResponseEncryptionAlg
    self.credentialResponseEncryptionMethod = credentialResponseEncryptionMethod
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
  }
}

public struct MsoMdocIssuanceRequest {
  public let format: String
  public let proof: ProofType?
  public let credentialEncryptionJwk: JWK?
  public let credentialResponseEncryptionAlg: JWEAlgorithm?
  public let credentialResponseEncryptionMethod: JOSEEncryptionMethod?
  public let doctype: String
  public let claims: [Namespace: [ClaimName: SupportedCredential]]
  
  public init(
    format: String,
    proof: ProofType?,
    credentialEncryptionJwk: JWK?,
    credentialResponseEncryptionAlg: JWEAlgorithm?,
    credentialResponseEncryptionMethod: JOSEEncryptionMethod?,
    doctype: String,
    claims: [Namespace: [ClaimName: SupportedCredential]]
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
    claims: [Namespace: [ClaimName: SupportedCredential]]
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

