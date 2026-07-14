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

enum ClientAttestationError: Error, LocalizedError {
  case notSigned
  case invalidAlgorithm(allowedAlgorithms: [String])
  case invalidPayload
  case invalidClientId
  case missingSubject
  case missingCnfClaim
  case missingJwkClaim
  case missingExpirationClaim
  case missingIssuerClaim
  case missingJtiClaim
  case missingAudienceClaim
  case invalidClient

  // TS3 Wallet Instance Attestation validation
  case invalidTypHeader(expected: String, got: String?)
  case blankClaim(name: String)
  case missingWalletName
  case missingWalletVersion
  case missingWalletSolutionCertificationInformation
  case missingClientStatus
  case invalidClientStatus(reason: String)
  case invalidStatusListReference(reason: String)
  case cnfJwkNotPublic
  case invalidJwk(reason: String)

  var errorDescription: String? {
    switch self {
    case .notSigned: return "Invalid Attestation JWT. Not properly signed."
    case .invalidAlgorithm(let allowed):
      let list = allowed.sorted().joined(separator: ", ")
      return "Invalid Attestation JWT. Signature algorithm must be one of: \(list)."
    case .invalidPayload: return "Invalid Attestation JWT. Cannot parse payload."
    case .missingSubject: return "Invalid Attestation JWT. Misses `sub` claim."
    case .missingCnfClaim: return "Invalid Attestation JWT. Misses `cnf` claim."
    case .missingJwkClaim: return "Invalid Attestation JWT. Misses `jwk` claim from `cnf`."
    case .missingExpirationClaim: return "Invalid Attestation JWT. Misses `exp` claim."
    case .missingIssuerClaim: return "Invalid Attestation JWT. Misses `iss` claim."
    case .missingJtiClaim: return "Invalid Attestation JWT. Misses `jti` claim."
    case .missingAudienceClaim: return "Invalid Attestation JWT. Misses `aud` claim."
    case .invalidClientId: return "Invalid client ID"
    case .invalidClient: return "Invalid Client"
    case .invalidTypHeader(let expected, let got):
      return "Invalid Attestation JWT. Header `typ` must be `\(expected)`, got `\(got ?? "<missing>")`."
    case .blankClaim(let name):
      return "Invalid Attestation JWT. Claim `\(name)` must not be blank."
    case .missingWalletName:
      return "Invalid Attestation JWT. Misses `wallet_name` claim."
    case .missingWalletVersion:
      return "Invalid Attestation JWT. Misses `wallet_version` claim."
    case .missingWalletSolutionCertificationInformation:
      return "Invalid Attestation JWT. Misses `wallet_solution_certification_information` claim."
    case .missingClientStatus:
      return "Invalid Attestation JWT. Misses `client_status` claim."
    case .invalidClientStatus(let reason):
      return "Invalid Attestation JWT. Invalid `client_status`: \(reason)."
    case .invalidStatusListReference(let reason):
      return "Invalid Attestation JWT. Invalid status list reference: \(reason)."
    case .cnfJwkNotPublic:
      return "Invalid Attestation JWT. `cnf.jwk` must be a public key."
    case .invalidJwk(let reason):
      return "Invalid Attestation JWT. Invalid `cnf.jwk`: \(reason)."
    }
  }
}
