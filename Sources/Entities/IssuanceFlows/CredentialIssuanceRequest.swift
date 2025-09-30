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
public let FORMAT_SD_JWT_VC = "dc+sd-jwt"
public let FORMAT_W3C_JSONLD_DATA_INTEGRITY = "ldp_vc"
public let FORMAT_W3C_JSONLD_SIGNED_JWT = "jwt_vc_json-ld"
public let FORMAT_W3C_SIGNED_JWT = "jwt_vc_json"

public enum CredentialIssuanceRequest: Sendable {
  case single(SingleCredential, IssuanceResponseEncryptionSpec?)
}

public enum SingleCredential: Sendable {
  case msoMdoc(MsoMdocFormat.MsoMdocSingleCredential)
  case sdJwtVc(SdJwtVcFormat.SdJwtVcSingleCredential)
}

public extension SingleCredential {
  
  var credentialConfigurationIdentifier: CredentialConfigurationIdentifier {
    switch self {
    case .msoMdoc(let credential):
      switch credential.requestPayload {
      case .identifierBased(let credentialConfigurationIdentifier, _):
        return credentialConfigurationIdentifier
      case .configurationBased(let credentialConfigurationIdentifier):
        return credentialConfigurationIdentifier
      }
    case .sdJwtVc(let credential):
      switch credential.requestPayload {
      case .identifierBased(let credentialConfigurationIdentifier, _):
        return credentialConfigurationIdentifier
      case .configurationBased(let credentialConfigurationIdentifier):
        return credentialConfigurationIdentifier
      }
    }
  }
  
  var proofs: [Proof] {
    switch self {
    case .msoMdoc(let credential):
      return credential.proofs
    case .sdJwtVc(let credential):
      return credential.proofs
    }
  }
  
  func toPayload(encryptionSpec: EncryptionSpec?) throws -> JSON {
    return switch self {
      case .msoMdoc(let credential):
        try createPayload(
          proofs: credential.proofs.proofs(),
          credentialId: extractCredentialId(
            from: credential.requestPayload
          ),
          encryptionSpec: encryptionSpec,
          encryption: credential.requestedCredentialResponseEncryption
        )
        
      case .sdJwtVc(let credential):
        try createPayload(
          proofs: credential.proofs.proofs(),
          credentialId: extractCredentialId(
            from: credential.requestPayload
          ),
          encryptionSpec: encryptionSpec,
          encryption: credential.requestedCredentialResponseEncryption
        )
      }
  }
  
  // Helper function to extract the credential ID
  private func extractCredentialId(from payload: IssuanceRequestPayload?) -> (id: String, value: String?) {
    switch payload {
    case .identifierBased(_, let identifier):
      return ("credential_identifier", identifier.value)
    case .configurationBased(let identifier):
      return ("credential_configuration_id", identifier.value)
    case .none:
      return ("", nil)
    }
  }
  
  // Helper function to create the JSON dictionary
  private func createPayload(
    proofs: ProofsTO?,
    credentialId: (id: String, value: String?),
    additionalFields: [String: Any?] = [:],
    encryptionSpec: EncryptionSpec?,
    encryption: RequestedCredentialResponseEncryption
  ) throws -> JSON {
    var dictionary: [String: Any?] = additionalFields
    dictionary[credentialId.id] = credentialId.value
    
    switch encryption {
    case .notRequested:
      return try JSON.createFrom(
        proofs: proofs,
        dictionary: dictionary.compactMapValues { $0 }
      )
      
    case .requested(
      let encryptionJwk,
      _,
      let responseEncryptionAlg,
      let responseEncryptionMethod
    ):
      if let encryptionSpec {
        dictionary[EncryptionKey.credentialResponseEncryption.rawValue] = [
          EncryptionKey.jwk: try encryptionJwk.toDictionary(),
          EncryptionKey.alg: responseEncryptionAlg.name,
          EncryptionKey.enc: responseEncryptionMethod.name
        ]
      }
      
      return try JSON.createFrom(
        proofs: proofs,
        dictionary: dictionary.compactMapValues { $0 }
      )
    }
  }
}

private extension Array where Element == Proof {
  func proofs() -> ProofsTO? {
    if self.isEmpty {
      return nil
      
    } else if self.count == 1 {
      if let first = self.first {
        return .init(jwtProofs: [first.proof])
      } else {
        return nil
      }
      
    } else {
      let jwtProofs: [String] = self.compactMap { proof in
        switch proof {
        case .jwt(let jwt):
          return jwt
        case .attestation:
          return nil
        }
      }
      let attestationProofs: [String] = self.compactMap { proof in
        switch proof {
        case .jwt:
          return nil
        case .attestation(let jwt):
          return jwt.jws.compactSerializedString
        }
      }
      let proofsTO = !jwtProofs.isEmpty ?
      ProofsTO(jwtProofs: jwtProofs) :
      ProofsTO(attestationProofs: attestationProofs)
      
      return proofsTO
    }
  }
}

private extension JSON {
  static func toJSON(_ proofs: ProofsTO?) -> JSON? {
    if let proofs = proofs {
      return try? .init(["proofs": proofs.toDictionary()])
    } else {
      return nil
    }
  }
  
  static func createFrom(proofs: ProofsTO?, dictionary: [String: Any?]) throws -> JSON {
    var json: JSON = Self.toJSON(proofs) ?? JSON([:])
    try json.merge(with: JSON(
      dictionary.compactMapValues { $0 }
    ))
    return json
  }
}
