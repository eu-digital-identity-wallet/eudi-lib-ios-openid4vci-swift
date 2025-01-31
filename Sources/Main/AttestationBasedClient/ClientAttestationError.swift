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
  
  var errorDescription: String? {
    switch self {
    case .notSigned: return "Invalid Attestation JWT. Not properly signed."
    case .invalidPayload: return "Invalid Attestation JWT. Cannot parse payload."
    case .missingSubject: return "Invalid Attestation JWT. Missing subject claim."
    case .missingCnfClaim: return "Invalid Attestation JWT. Missing cnf claim."
    case .missingJwkClaim: return "Invalid Attestation JWT. Missing jwk claim from cnf."
    case .missingExpirationClaim: return "Invalid Attestation JWT. Missing exp claim."
    case .missingIssuerClaim: return "Invalid Attestation JWT. Missing issuer claim."
    case .missingJtiClaim: return "Invalid Attestation JWT. Missing jti claim."
    case .missingAudienceClaim: return "Invalid Attestation JWT. Missing aud claim."
    case .invalidClientId: return "Invalid client ID"
    case .invalidClient: return "Invalid Client"
    }
  }
}

