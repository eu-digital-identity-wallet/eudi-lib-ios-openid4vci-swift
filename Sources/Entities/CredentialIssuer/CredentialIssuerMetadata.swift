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

public struct CredentialIssuerMetadata: Codable, Equatable {
  let credentialIssuerIdentifier: CredentialIssuerId
  let authorizationServers: [URL]
  let credentialEndpoint: CredentialIssuerEndpoint
  let batchCredentialEndpoint: CredentialIssuerEndpoint?
  let deferredCredentialEndpoint: CredentialIssuerEndpoint?
  let credentialResponseEncryption: CredentialResponseEncryption
  let requireCredentialResponseEncryption: Bool
  
  let credentialsSupported: [SupportedCredential]
  let credentialsSupportedMap: [CredentialIdentifier: SupportedCredential]
  
  let display: [Display]
  
  enum CodingKeys: String, CodingKey {
    case credentialIssuerIdentifier = "credential_issuer"
    case authorizationServers = "authorization_servers"
    case credentialEndpoint = "credential_endpoint"
    case batchCredentialEndpoint = "batch_credential_endpoint"
    case deferredCredentialEndpoint = "deferred_credential_endpoint"
    case credentialResponseEncryptionAlgorithmsSupported = "credential_response_encryption_alg_values_supported"
    case credentialResponseEncryptionMethodsSupported = "credential_response_encryption_enc_values_supported"
    case requireCredentialResponseEncryption = "require_credential_response_encryption"
    case credentialsSupported = "credentials_supported"
    case display = "display"
  }
  
  public init(
    credentialIssuerIdentifier: CredentialIssuerId,
    authorizationServers: [URL],
    credentialEndpoint: CredentialIssuerEndpoint,
    batchCredentialEndpoint: CredentialIssuerEndpoint?,
    deferredCredentialEndpoint: CredentialIssuerEndpoint?,
    credentialResponseEncryption: CredentialResponseEncryption = .notRequired,
    requireCredentialResponseEncryption: Bool?,
    credentialsSupported: [SupportedCredential],
    display: [Display]?
  ) {
    self.credentialIssuerIdentifier = credentialIssuerIdentifier
    self.authorizationServers = authorizationServers
    self.credentialEndpoint = credentialEndpoint
    self.batchCredentialEndpoint = batchCredentialEndpoint
    self.deferredCredentialEndpoint = deferredCredentialEndpoint
    self.credentialResponseEncryption = credentialResponseEncryption
    self.requireCredentialResponseEncryption = requireCredentialResponseEncryption ?? false
    
    self.credentialsSupported = credentialsSupported
    self.credentialsSupportedMap = [:]
    
    self.display = display ?? []
  }
  
  // Implement a custom init(from decoder:) method to handle decoding.
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    
    // Decode each property as necessary, handling optionals and conversions.
    credentialIssuerIdentifier = try container.decode(CredentialIssuerId.self, forKey: .credentialIssuerIdentifier)
    authorizationServers = try container.decode([URL].self, forKey: .authorizationServers)
    credentialEndpoint = try container.decode(CredentialIssuerEndpoint.self, forKey: .credentialEndpoint)
    batchCredentialEndpoint = try container.decodeIfPresent(CredentialIssuerEndpoint.self, forKey: .batchCredentialEndpoint)
    deferredCredentialEndpoint = try container.decodeIfPresent(CredentialIssuerEndpoint.self, forKey: .deferredCredentialEndpoint)
    
    if let credentialResponseEncryptionAlgorithmsSupported = try? container.decodeIfPresent([JWEAlgorithm].self, forKey: .credentialResponseEncryptionAlgorithmsSupported),
       let credentialResponseEncryptionMethodsSupported = try? container.decodeIfPresent([JOSEEncryptionMethod].self, forKey: .credentialResponseEncryptionMethodsSupported) {
      credentialResponseEncryption = .required(
        algorithmsSupported: credentialResponseEncryptionAlgorithmsSupported,
        encryptionMethodsSupported: credentialResponseEncryptionMethodsSupported
      )
    } else {
      credentialResponseEncryption = .notRequired
    }
    
    requireCredentialResponseEncryption = try container.decodeIfPresent(Bool.self, forKey: .requireCredentialResponseEncryption) ?? false
    
    let json = try container.decodeIfPresent(JSON.self, forKey: .credentialsSupported) ?? []
    var map: [CredentialIdentifier: SupportedCredential] = [:]
    for (key, value): (String, JSON) in json {
      // Transform the value (for example, convert to uppercase if it's a string)
      if let dictionary = value.dictionary,
         let credJson = JSON(rawValue: dictionary){
        
        let credentialIdentifier: CredentialIdentifier = try .init(value: key)
        guard let format = credJson["format"].string else {
          throw ValidationError.error(reason: "Profile format not found")
        }
        
        switch format {
        case MsoMdocFormat.FORMAT:
          let profile = try MsoMdocFormat.CredentialSupported(json: credJson)
          map[credentialIdentifier] = .msoMdoc(profile)
        case W3CSignedJwtFormat.FORMAT:
          let profile = try W3CSignedJwtFormat.CredentialSupported(json: credJson)
          map[credentialIdentifier] = .w3CSignedJwt(profile)
        case SdJwtVcFormat.FORMAT:
          let profile = try SdJwtVcFormat.CredentialSupported(json: credJson)
          map[credentialIdentifier] = .sdJwtVc(profile)
        case W3CJsonLdSignedJwtFormat.FORMAT:
          let profile = try W3CJsonLdSignedJwtFormat.CredentialSupported(json: credJson)
          map[credentialIdentifier] = .w3CJsonLdSignedJwt(profile)
        case W3CJsonLdDataIntegrityFormat.FORMAT:
          let profile = try W3CJsonLdDataIntegrityFormat.CredentialSupported(json: credJson)
          map[credentialIdentifier] = .w3CJsonLdDataIntegrity(profile)
        default: throw ValidationError.error(reason: "Unknow credential format")
        }
      }
    }
    
    credentialsSupported = Array(map.values)
    credentialsSupportedMap = map
    
    display = try container.decodeIfPresent([Display].self, forKey: .display) ?? []
  }
  
  // Implement an encode(to:) method to handle encoding.
  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    
    // Encode each property as necessary, handling optionals and conversions.
    try container.encode(credentialIssuerIdentifier, forKey: .credentialIssuerIdentifier)
    try container.encode(authorizationServers, forKey: .authorizationServers)
    try container.encode(credentialEndpoint, forKey: .credentialEndpoint)
    try container.encode(batchCredentialEndpoint, forKey: .batchCredentialEndpoint)
    try container.encode(deferredCredentialEndpoint, forKey: .deferredCredentialEndpoint)
    
    switch credentialResponseEncryption {
    case .notRequired: break
    case .required(
      let algorithmsSupported,
      let encryptionMethodsSupported
    ):
      try container.encode(algorithmsSupported, forKey: .credentialResponseEncryptionAlgorithmsSupported)
      try container.encode(encryptionMethodsSupported, forKey: .credentialResponseEncryptionMethodsSupported)
    }
    
    try container.encode(requireCredentialResponseEncryption, forKey: .requireCredentialResponseEncryption)
    try container.encode(credentialsSupported, forKey: .credentialsSupported)
    try container.encode(display, forKey: .display)
  }
  
  public static func == (lhs: CredentialIssuerMetadata, rhs: CredentialIssuerMetadata) -> Bool {
    lhs.credentialIssuerIdentifier == rhs.credentialIssuerIdentifier
  }
}
