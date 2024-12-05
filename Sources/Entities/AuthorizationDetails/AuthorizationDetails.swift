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

// MARK: - OidCredentialAuthorizationDetail

public protocol OidCredentialAuthorizationDetail {}

// MARK: - ByCredentialConfiguration

public struct ByCredentialConfiguration: Codable, OidCredentialAuthorizationDetail {
  public let credentialConfigurationId: CredentialConfigurationIdentifier
  public let credentialIdentifiers: [CredentialIdentifier]?
  
  public init(credentialConfigurationId: CredentialConfigurationIdentifier, credentialIdentifiers: [CredentialIdentifier]? = nil) {
    self.credentialConfigurationId = credentialConfigurationId
    self.credentialIdentifiers = credentialIdentifiers
  }
}

// MARK: - ByFormat

public enum ByFormat: Codable, OidCredentialAuthorizationDetail {
  case msoMdocAuthorizationDetails(MsoMdocAuthorizationDetails)
  case sdJwtVcAuthorizationDetails(SdJwtVcAuthorizationDetails)
  
  public enum CodingKeys: String, CodingKey {
    case type, details
  }
  
  public enum ByFormatType: String, Codable {
    case msoMdocAuthorizationDetails
    case sdJwtVcAuthorizationDetails
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let type = try container.decode(ByFormatType.self, forKey: .type)
    let nestedDecoder = try container.superDecoder(forKey: .details)
    
    switch type {
    case .msoMdocAuthorizationDetails:
      let details = try MsoMdocAuthorizationDetails(from: nestedDecoder)
      self = .msoMdocAuthorizationDetails(details)
    case .sdJwtVcAuthorizationDetails:
      let details = try SdJwtVcAuthorizationDetails(from: nestedDecoder)
      self = .sdJwtVcAuthorizationDetails(details)
    }
  }
  
  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    
    switch self {
    case .msoMdocAuthorizationDetails(let details):
      try container.encode(ByFormatType.msoMdocAuthorizationDetails, forKey: .type)
      try details.encode(to: container.superEncoder(forKey: .details))
    case .sdJwtVcAuthorizationDetails(let details):
      try container.encode(ByFormatType.sdJwtVcAuthorizationDetails, forKey: .type)
      try details.encode(to: container.superEncoder(forKey: .details))
    }
  }
}

// MARK: - MsoMdocAuthorizationDetails

public struct MsoMdocAuthorizationDetails: Codable {
  public let doctype: String
  
  public init(doctype: String) {
    self.doctype = doctype
  }
}

// MARK: - SdJwtVcAuthorizationDetails

public struct SdJwtVcAuthorizationDetails: Codable {
  public let vct: String
  
  public init(vct: String) {
    self.vct = vct
  }
}
