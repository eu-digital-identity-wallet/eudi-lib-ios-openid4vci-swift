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

public enum SupportedCredential: Codable {
  case scope(Scope)
  case msoMdoc(MsoMdocFormat.CredentialSupported)
  case w3CSignedJwt(W3CSignedJwtFormat.CredentialSupported)
  case w3CJsonLdSignedJwt(W3CJsonLdSignedJwtFormat.CredentialSupported)
  case w3CJsonLdDataIntegrity(W3CJsonLdDataIntegrityFormat.CredentialSupported)
  case sdJwtVc(SdJwtVcFormat.CredentialSupported)
}

public extension SupportedCredential {
  
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
    claimSet: ClaimSet?,
    proof: Proof? = nil,
    responseEncryptionSpecProvider: (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
  ) throws -> CredentialIssuanceRequest {
    switch self {
    case .msoMdoc(let credentialSupported):
      if let proof,
         let proofTypesSupported = credentialSupported.proofTypesSupported,
         proofTypesSupported.contains(proof.type()) {
        if !proofTypesSupported.contains(proof.type()) {
          throw ValidationError.error(reason: "Provided proof type \(proof.type()) is not one of supported [\(proofTypesSupported)].")
        }
      }
      
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
     
      return try credentialSupported.toIssuanceRequest(
        responseEncryptionSpec: responseEncryptionSpec,
        claimSet: claimSet,
        proof: proof
      )

    case .sdJwtVc(let credentialSupported):
      if let proof,
         let proofTypesSupported = credentialSupported.proofTypesSupported,
         proofTypesSupported.contains(proof.type()) {
        if !proofTypesSupported.contains(proof.type()) {
          throw ValidationError.error(reason: "Provided proof type \(proof.type()) is not one of supported [\(proofTypesSupported)].")
        }
      }
      
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
     
      return try credentialSupported.toIssuanceRequest(
        responseEncryptionSpec: responseEncryptionSpec,
        claimSet: claimSet,
        proof: proof
      )
    default:
      throw ValidationError.error(reason: "Unsupported profile for issueance request")
    }
  }
}
