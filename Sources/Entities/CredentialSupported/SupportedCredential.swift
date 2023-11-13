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
  case msoMdoc(MsoMdocProfile.CredentialSupported)
  case w3CSignedJwt(W3CSignedJwtProfile.CredentialSupported)
  case w3CJsonLdSignedJwt(W3CJsonLdSignedJwtProfile.CredentialSupported)
  case w3CJsonLdDataIntegrity(W3CJsonLdDataIntegrityProfile.CredentialSupported)
  case sdJwtVc(SdJwtVcProfile.CredentialSupported)
}

public extension SupportedCredential {
  func toIssuanceRequest(
      claimSet: ClaimSet?,
      proof: Proof? = nil
  ) throws -> CredentialIssuanceRequest {
    switch self {
    case .msoMdoc(let credentialSupported):
      return credentialSupported.toIssuanceRequest(
        claimSet: claimSet,
        proof: proof
      )
    case .w3CSignedJwt(let credentialSupported):
      return credentialSupported.toIssuanceRequest(
        claimSet: claimSet,
        proof: proof
      )
    case .w3CJsonLdSignedJwt(let credentialSupported):
      return credentialSupported.toIssuanceRequest(
        claimSet: claimSet,
        proof: proof
      )
    case .w3CJsonLdDataIntegrity(let credentialSupported):
      return credentialSupported.toIssuanceRequest(
        claimSet: claimSet,
        proof: proof
      )
    case .sdJwtVc(let credentialSupported):
      return credentialSupported.toIssuanceRequest(
        claimSet: claimSet,
        proof: proof
      )
    default:
      throw ValidationError.error(reason: "Unsupported profile for issueance request")
    }
  }
}
