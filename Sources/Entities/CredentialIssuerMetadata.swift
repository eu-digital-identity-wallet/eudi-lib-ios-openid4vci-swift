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
  let authorizationServer: URL
  let credentialEndpoint: CredentialIssuerEndpoint
  let batchCredentialEndpoint: CredentialIssuerEndpoint?
  let deferredCredentialEndpoint: CredentialIssuerEndpoint?
  let credentialResponseEncryptionAlgorithmsSupported: [JWEAlgorithm]?
  let credentialResponseEncryptionMethodsSupported: [JOSEEncryptionMethod]?
  let requireCredentialResponseEncryption: Bool
  let credentialsSupported: [SupportedCredential]
  let display: [Display]
  
  enum CodingKeys: String, CodingKey {
    case credentialIssuerIdentifier = "credential_issuer"
    case authorizationServer = "authorization_server"
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
    authorizationServer: URL,
    credentialEndpoint: CredentialIssuerEndpoint,
    batchCredentialEndpoint: CredentialIssuerEndpoint?,
    deferredCredentialEndpoint: CredentialIssuerEndpoint?,
    credentialResponseEncryptionAlgorithmsSupported: [JWEAlgorithm]? = nil,
    credentialResponseEncryptionMethodsSupported: [JOSEEncryptionMethod]? = nil,
    requireCredentialResponseEncryption: Bool?,
    credentialsSupported: [SupportedCredential],
    display: [Display]?
  ) {
    self.credentialIssuerIdentifier = credentialIssuerIdentifier
    self.authorizationServer = authorizationServer
    self.credentialEndpoint = credentialEndpoint
    self.batchCredentialEndpoint = batchCredentialEndpoint
    self.deferredCredentialEndpoint = deferredCredentialEndpoint
    self.credentialResponseEncryptionAlgorithmsSupported = credentialResponseEncryptionAlgorithmsSupported
    self.credentialResponseEncryptionMethodsSupported = credentialResponseEncryptionMethodsSupported
    self.requireCredentialResponseEncryption = requireCredentialResponseEncryption ?? false
    self.credentialsSupported = credentialsSupported
    self.display = display ?? []
  }
  
  // Implement a custom init(from decoder:) method to handle decoding.
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    
    // Decode each property as necessary, handling optionals and conversions.
    credentialIssuerIdentifier = try container.decode(CredentialIssuerId.self, forKey: .credentialIssuerIdentifier)
    authorizationServer = try container.decode(URL.self, forKey: .authorizationServer)
    credentialEndpoint = try container.decode(CredentialIssuerEndpoint.self, forKey: .credentialEndpoint)
    batchCredentialEndpoint = try container.decodeIfPresent(CredentialIssuerEndpoint.self, forKey: .batchCredentialEndpoint)
    deferredCredentialEndpoint = try container.decodeIfPresent(CredentialIssuerEndpoint.self, forKey: .deferredCredentialEndpoint)
    credentialResponseEncryptionAlgorithmsSupported = try container.decodeIfPresent([JWEAlgorithm].self, forKey: .credentialResponseEncryptionAlgorithmsSupported)
    credentialResponseEncryptionMethodsSupported = try container.decodeIfPresent([JOSEEncryptionMethod].self, forKey: .credentialResponseEncryptionMethodsSupported)
    requireCredentialResponseEncryption = try container.decodeIfPresent(Bool.self, forKey: .requireCredentialResponseEncryption) ?? false
    let credentialsSupportedJSON = try container.decodeIfPresent([JSON].self, forKey: .credentialsSupported) ?? []
    credentialsSupported = try credentialsSupportedJSON.map { json in
      guard let format = json["format"].string else {
        throw ValidationError.error(reason: "Profile format not found")
      }
      
      switch format {
      case MsoMdocProfile.FORMAT:
        let profile = try MsoMdocProfile.CredentialSupported(json: json)
        return .msoMdoc(profile)
      case W3CSignedJwtProfile.FORMAT:
        let profile = try W3CSignedJwtProfile.CredentialSupported(json: json)
        return .w3CSignedJwt(profile)
      case SdJwtVcProfile.FORMAT:
        let profile = try SdJwtVcProfile.CredentialSupported(json: json)
        return .sdJwtVc(profile)
      case W3CJsonLdSignedJwtProfile.FORMAT:
        let profile = try W3CJsonLdSignedJwtProfile.CredentialSupported(json: json)
        return .w3CJsonLdSignedJwt(profile)
      case W3CJsonLdDataIntegrityProfile.FORMAT:
        let profile = try W3CJsonLdDataIntegrityProfile.CredentialSupported(json: json)
        return .w3CJsonLdDataIntegrity(profile)
      default: throw ValidationError.error(reason: "Unknow credential format")
      }
    }
    display = try container.decodeIfPresent([Display].self, forKey: .display) ?? []
  }
  
  // Implement an encode(to:) method to handle encoding.
  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    
    // Encode each property as necessary, handling optionals and conversions.
    try container.encode(credentialIssuerIdentifier, forKey: .credentialIssuerIdentifier)
    try container.encode(authorizationServer, forKey: .authorizationServer)
    try container.encode(credentialEndpoint, forKey: .credentialEndpoint)
    try container.encode(batchCredentialEndpoint, forKey: .batchCredentialEndpoint)
    try container.encode(deferredCredentialEndpoint, forKey: .deferredCredentialEndpoint)
    try container.encode(credentialResponseEncryptionAlgorithmsSupported, forKey: .credentialResponseEncryptionAlgorithmsSupported)
    try container.encode(credentialResponseEncryptionMethodsSupported, forKey: .credentialResponseEncryptionMethodsSupported)
    try container.encode(requireCredentialResponseEncryption, forKey: .requireCredentialResponseEncryption)
    try container.encode(credentialsSupported, forKey: .credentialsSupported)
    try container.encode(display, forKey: .display)
  }
  
  public static func == (lhs: CredentialIssuerMetadata, rhs: CredentialIssuerMetadata) -> Bool {
    lhs.credentialIssuerIdentifier == rhs.credentialIssuerIdentifier
  }
}
