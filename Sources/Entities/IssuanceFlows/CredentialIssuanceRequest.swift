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

public typealias Namespace = String
public typealias ClaimName = String

public typealias MsoMdocClaims = [Namespace: [ClaimName: Claim]]

public protocol CredentialIssuanceRequest {
  var format: String { get }
  var proof: ProofType? { get }
  var credentialEncryptionJwk: JWK? { get }
  var credentialResponseEncryptionAlg: JWEAlgorithm? { get }
  var credentialResponseEncryptionMethod: JOSEEncryptionMethod? { get }
}

public struct BatchCredentials: Codable {
  public let credentialRequests: [SingleCredential]
}

public struct DeferredCredentialRequest: Codable {
  let transactionId: String
  let token: IssuanceAccessToken
}

public struct SingleCredential: Codable, CredentialIssuanceRequest {
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

public struct MsoMdocIssuanceRequest: CredentialIssuanceRequest {
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

