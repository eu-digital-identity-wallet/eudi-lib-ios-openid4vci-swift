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

public enum CredentialSupported: Codable {
  case scope(Scope)
  case msoMdoc(MsoMdocFormat.CredentialConfiguration)
  case w3CSignedJwt(W3CSignedJwtFormat.CredentialConfiguration)
  case w3CJsonLdSignedJwt(W3CJsonLdSignedJwtFormat.CredentialConfiguration)
  case w3CJsonLdDataIntegrity(W3CJsonLdDataIntegrityFormat.CredentialConfiguration)
  case sdJwtVc(SdJwtVcFormat.CredentialConfiguration)
}

public extension CredentialSupported {
  
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
    claimSet: ClaimSet? = nil,
    proof: Proof? = nil,
    credentialIdentifier: CredentialIdentifier? = nil,
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) throws -> CredentialIssuanceRequest {
    switch self {
    case .msoMdoc(let credentialConfiguration):
      let issuerEncryption = requester.issuerMetadata.credentialResponseEncryption
      let responseEncryptionSpec = responseEncryptionSpecProvider(issuerEncryption)
      
      if let responseEncryptionSpec {
        switch issuerEncryption {
        case .notRequired: break
        case .required(
          let algorithmsSupported,
          let encryptionMethodsSupported
        ):
          if !algorithmsSupported.contains(responseEncryptionSpec.algorithm) {
            throw CredentialIssuanceError.responseEncryptionAlgorithmNotSupportedByIssuer
          }
          
          if !encryptionMethodsSupported.contains(responseEncryptionSpec.encryptionMethod) {
            throw CredentialIssuanceError.responseEncryptionMethodNotSupportedByIssuer
          }
        }
      }
     
      return try credentialConfiguration.toIssuanceRequest(
        responseEncryptionSpec: issuerEncryption.notRequired ? nil : responseEncryptionSpec,
        claimSet: claimSet,
        proof: proof
      )

    case .sdJwtVc(let credentialConfiguration):
      let issuerEncryption = requester.issuerMetadata.credentialResponseEncryption
      let responseEncryptionSpec = responseEncryptionSpecProvider(issuerEncryption)
      
      if let responseEncryptionSpec {
        switch issuerEncryption {
        case .notRequired: break
        case .required(
          let algorithmsSupported,
          let encryptionMethodsSupported
        ):
          if !algorithmsSupported.contains(responseEncryptionSpec.algorithm) {
            throw CredentialIssuanceError.responseEncryptionAlgorithmNotSupportedByIssuer
          }
          
          if !encryptionMethodsSupported.contains(responseEncryptionSpec.encryptionMethod) {
            throw CredentialIssuanceError.responseEncryptionMethodNotSupportedByIssuer
          }
        }
      }
     
      return try credentialConfiguration.toIssuanceRequest(
        responseEncryptionSpec: issuerEncryption.notRequired ? nil : responseEncryptionSpec,
        claimSet: claimSet,
        proof: proof
      )
    default:
      throw ValidationError.error(reason: "Unsupported profile for issuance request")
    }
  }
}
