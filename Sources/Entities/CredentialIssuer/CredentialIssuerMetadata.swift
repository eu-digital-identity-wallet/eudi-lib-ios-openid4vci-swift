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
  public let credentialIssuerIdentifier: CredentialIssuerId
  public let authorizationServers: [URL]
  public let credentialEndpoint: CredentialIssuerEndpoint
  public let batchCredentialEndpoint: CredentialIssuerEndpoint?
  public let deferredCredentialEndpoint: CredentialIssuerEndpoint?
  public let notificationEndpoint: CredentialIssuerEndpoint?
  public let credentialResponseEncryption: CredentialResponseEncryption
  public let requireCredentialResponseEncryption: Bool
  public let credentialConfigurationsSupported: [CredentialIdentifier: SupportedCredential]
  
  public let display: [Display]
  
  public enum CodingKeys: String, CodingKey {
    case credentialIssuerIdentifier = "credential_issuer"
    case authorizationServers = "authorization_servers"
    case credentialEndpoint = "credential_endpoint"
    case batchCredentialEndpoint = "batch_credential_endpoint"
    case deferredCredentialEndpoint = "deferred_credential_endpoint"
    case notificationEndpoint = "notification_endpoint"
    case credentialResponseEncryptionAlgorithmsSupported = "credential_response_encryption_alg_values_supported"
    case credentialResponseEncryptionMethodsSupported = "credential_response_encryption_enc_values_supported"
    case requireCredentialResponseEncryption = "require_credential_response_encryption"
    case credentialConfigurationsSupported = "credential_configurations_supported"
    case display = "display"
  }
  
  public init(
    credentialIssuerIdentifier: CredentialIssuerId,
    authorizationServers: [URL],
    credentialEndpoint: CredentialIssuerEndpoint,
    batchCredentialEndpoint: CredentialIssuerEndpoint?,
    deferredCredentialEndpoint: CredentialIssuerEndpoint?,
    notificationEndpoint: CredentialIssuerEndpoint?,
    credentialResponseEncryption: CredentialResponseEncryption = .notRequired,
    requireCredentialResponseEncryption: Bool?,
    credentialConfigurationsSupported: [CredentialIdentifier: SupportedCredential],
    display: [Display]?
  ) {
    self.credentialIssuerIdentifier = credentialIssuerIdentifier
    self.authorizationServers = authorizationServers
    
    self.credentialEndpoint = credentialEndpoint
    self.batchCredentialEndpoint = batchCredentialEndpoint
    self.deferredCredentialEndpoint = deferredCredentialEndpoint
    self.notificationEndpoint = notificationEndpoint
    
    self.credentialResponseEncryption = credentialResponseEncryption
    self.requireCredentialResponseEncryption = requireCredentialResponseEncryption ?? false
    self.credentialConfigurationsSupported = credentialConfigurationsSupported
    self.display = display ?? []
  }
  
  // Implement a custom init(from decoder:) method to handle decoding.
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    
    // Decode each property as necessary, handling optionals and conversions.
    credentialIssuerIdentifier = try container.decode(CredentialIssuerId.self, forKey: .credentialIssuerIdentifier)
    
    let servers = try? container.decode([URL].self, forKey: .authorizationServers)
    authorizationServers = servers ?? [credentialIssuerIdentifier.url]
    
    credentialEndpoint = try container.decode(CredentialIssuerEndpoint.self, forKey: .credentialEndpoint)
    batchCredentialEndpoint = try container.decodeIfPresent(CredentialIssuerEndpoint.self, forKey: .batchCredentialEndpoint)
    deferredCredentialEndpoint = try container.decodeIfPresent(CredentialIssuerEndpoint.self, forKey: .deferredCredentialEndpoint)
    notificationEndpoint = try container.decodeIfPresent(CredentialIssuerEndpoint.self, forKey: .notificationEndpoint)
    
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
    
    let json = try container.decodeIfPresent(JSON.self, forKey: .credentialConfigurationsSupported) ?? []
    var mapIdentifierCredential: [CredentialIdentifier: SupportedCredential] = [:]
    for (key, value): (String, JSON) in json {
      if let dictionary = value.dictionary,
         let credJson = JSON(rawValue: dictionary) {
        
        let credentialIdentifier: CredentialIdentifier = try .init(value: key)
        guard let format = credJson["format"].string else {
          throw ValidationError.error(reason: "Profile format not found")
        }
        
        switch format {
        case MsoMdocFormat.FORMAT:
          let profile = try MsoMdocFormat.CredentialConfiguration(json: credJson)
          mapIdentifierCredential[credentialIdentifier] = .msoMdoc(profile)
        case W3CSignedJwtFormat.FORMAT:
          let profile = try W3CSignedJwtFormat.CredentialConfiguration(json: credJson)
          mapIdentifierCredential[credentialIdentifier] = .w3CSignedJwt(profile)
        case SdJwtVcFormat.FORMAT:
          let profile = try SdJwtVcFormat.CredentialConfiguration(json: credJson)
          mapIdentifierCredential[credentialIdentifier] = .sdJwtVc(profile)
        case W3CJsonLdSignedJwtFormat.FORMAT:
          let profile = try W3CJsonLdSignedJwtFormat.CredentialConfiguration(json: credJson)
          mapIdentifierCredential[credentialIdentifier] = .w3CJsonLdSignedJwt(profile)
        case W3CJsonLdDataIntegrityFormat.FORMAT:
          let profile = try W3CJsonLdDataIntegrityFormat.CredentialConfiguration(json: credJson)
          mapIdentifierCredential[credentialIdentifier] = .w3CJsonLdDataIntegrity(profile)
        default: throw ValidationError.error(reason: "Unknow credential format")
        }
      }
    }
    
    credentialConfigurationsSupported = mapIdentifierCredential
    
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
    try container.encode(notificationEndpoint, forKey: .notificationEndpoint)
    
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
    try container.encode(credentialConfigurationsSupported, forKey: .credentialConfigurationsSupported)
    try container.encode(display, forKey: .display)
  }
  
  public static func == (lhs: CredentialIssuerMetadata, rhs: CredentialIssuerMetadata) -> Bool {
    lhs.credentialIssuerIdentifier == rhs.credentialIssuerIdentifier
  }
}
