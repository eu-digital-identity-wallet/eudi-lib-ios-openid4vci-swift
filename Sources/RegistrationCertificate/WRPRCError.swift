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

/// Errors raised while extracting, verifying, or enforcing the WRP Registration Certificate
/// (ETSI TS 119 475 v1.1.1) during issuance authorization.
public enum WRPRCError: LocalizedError, Sendable {

  /// The issuer metadata does not carry an `issuer_info` container, or the
  /// container is empty. Distinct from `.missingRequiredRegistrationCertificate`
  /// where `issuer_info` exists but has no `registration_cert`-format entry.
  case missingIssuerInfo

  /// No WRP Registration Certificate was found in issuer metadata `issuer_info`
  /// (the container exists but has no `registration_cert`-format entry).
  case missingRequiredRegistrationCertificate

  /// More than one WRP Registration Certificate was found in `issuer_info`.
  case multipleRegistrationCertificates

  /// The WRP Registration Certificate is not well-formed. `cause` describes the specific failure.
  case malformedRegistrationCertificate(cause: String)

  /// The WRP Registration Certificate's signing certificate chain was rejected by the configured trust.
  case registrationCertificateNotTrusted

  /// The metadata carries a WRPRC but no WRPAC was captured during metadata
  /// resolution — a configuration invariant should prevent this, but the check
  /// exists in the authorizer for defence in depth.
  case missingWrpac

  /// Policy evaluation returned `.notGranted(error:)`.
  case policyNotMet(PolicyViolation)

  public var errorDescription: String? {
    switch self {
    case .missingIssuerInfo:
      return "Issuer metadata does not carry an `issuer_info` container, or the container is empty"
    case .missingRequiredRegistrationCertificate:
      return "No WRP Registration Certificate found in issuer metadata issuer_info"
    case .multipleRegistrationCertificates:
      return "More than one WRP Registration Certificate found in issuer_info; exactly one is required"
    case .malformedRegistrationCertificate(let cause):
      return "Malformed WRP Registration Certificate: \(cause)"
    case .registrationCertificateNotTrusted:
      return "WRP Registration Certificate signing chain is not trusted"
    case .missingWrpac:
      return "WRPAC is not available on the issuer metadata; " +
             "ensure OpenId4VCIConfig.issuerMetadataPolicy is .requireSigned(.byCertificateChain(...))."
    case .policyNotMet(let violation):
      return "WRPRC policy not met: \(violation.value)"
    }
  }
}
