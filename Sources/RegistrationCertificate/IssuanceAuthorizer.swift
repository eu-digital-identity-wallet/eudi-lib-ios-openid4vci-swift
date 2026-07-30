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

/// Extracts the WRP Registration Certificate (WRPRC) that accompanies a resolved
/// `CredentialOffer` and applies the configured `RegistrationCertificatePolicy`
/// to authorize the issuance transaction.
public actor IssuanceAuthorizer {

  private let policy: RegistrationCertificatePolicy

  public init(policy: RegistrationCertificatePolicy) {
    self.policy = policy
  }

  /// Authorizes the resolved `credentialOffer` against the configured WRPRC policy.
  ///
  /// - Returns: The warnings produced by the policy validator.
  ///   Empty means the policy applied cleanly.
  /// - Throws: `WRPRCError` if the WRPRC is missing / multiple / WRPAC missing,
  ///   or if the policy returned `.notGranted`.
  public func authorize(credentialOffer: CredentialOffer) async throws -> [String: [PolicyViolation]] {

    let issuerMetadata = credentialOffer.credentialIssuerMetadata
    
    guard let issuerInfo = issuerMetadata.issuerInfo, !issuerInfo.attestations.isEmpty else {
      throw WRPRCError.missingIssuerInfo
    }

    let wrprcAttestations = issuerInfo.attestations.filter {
      $0.format == ETSI119472Part3.REGISTRATION_CERT
    }

    // Cardinality: exactly one REGISTRATION_CERT attestation.
    guard !wrprcAttestations.isEmpty else {
      throw WRPRCError.missingRequiredRegistrationCertificate
    }
    guard wrprcAttestations.count == 1 else {
      throw WRPRCError.multipleRegistrationCertificates
    }

    let wrprc = wrprcAttestations[0].data

    // Compute offered credential configurations for this credential offer.
    let offeredConfigurations = issuerMetadata.credentialsSupported
      .filter { credentialOffer.credentialConfigurationIdentifiers.contains($0.key) }

    guard let wrpac = issuerMetadata.wrpac else {
      throw WRPRCError.missingWrpac
    }

    // Invoke the consumer-supplied policy validator.
    let authorization = await policy.authorize(wrpac, wrprc, offeredConfigurations)

    switch authorization {
    case .granted(let warnings):
      return warnings
    case .notGranted(let error):
      throw WRPRCError.policyNotMet(error)
    }
  }
}
