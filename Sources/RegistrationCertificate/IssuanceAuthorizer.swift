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
import Security
@preconcurrency import JOSESwift
@preconcurrency import SwiftyJSON

/// Extracts and validates the WRP Registration Certificate (WRPRC) that accompanies
/// a resolved `CredentialOffer` and applies the configured
/// `RegistrationCertificatePolicy` to authorize the issuance transaction.
public actor IssuanceAuthorizer {

  private let policy: RegistrationCertificatePolicy

  public init(policy: RegistrationCertificatePolicy) {
    self.policy = policy
  }

  /// Authorizes the resolved `credentialOffer` against the configured WRPRC policy.
  ///
  /// - Returns: The `.warning` violations produced by the policy validator, if any.
  ///   Empty means the policy applied cleanly.
  /// - Throws: `WRPRCError` if the WRPRC is missing/multiple/malformed/untrusted,
  ///   or if the policy validator produced any `.error` violations.
  public func authorize(credentialOffer: CredentialOffer) async throws -> [PolicyViolation] {

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

    let wrprcAttestation = wrprcAttestations[0]

    // Parse the compact-serialized JWT.
    let jws: JWS
    do {
      jws = try JWS(compactSerialization: wrprcAttestation.data)
    } catch {
      throw WRPRCError.malformedRegistrationCertificate(
        cause: "Invalid WRPRC JWT: \(error.localizedDescription)"
      )
    }

    // Enforce JOSE header `typ` per ETSI 119475.
    guard jws.header.typ == ETSI119475.REG_CERT_HEADER_TYPE else {
      throw WRPRCError.malformedRegistrationCertificate(
        cause: "Unexpected JWT typ '\(jws.header.typ ?? "")'. Expected '\(ETSI119475.REG_CERT_HEADER_TYPE)'."
      )
    }

    // x5c chain must be present and every entry must parse
    let chain = jws.header.x5c ?? []
    guard !chain.isEmpty else {
      throw WRPRCError.malformedRegistrationCertificate(cause: "Missing x5c header on WRPRC JWT")
    }
    try assertAllCertificatesParse(chain: chain)

    
    try assertLeafKeyIsAsymmetric(chain: chain)

    // Signature + chain trust via the shared verifier. Translate helper errors
    //    into WRPRC-domain errors.
    let verifiedJWS: JWS
    do {
      verifiedJWS = try await policy.issuerTrust.verify(jws: jws)
    } catch let error as JWSVerificationError {
      switch error {
      case .chainNotTrusted:
        throw WRPRCError.registrationCertificateNotTrusted
      case .invalidCertificateChain(let reason),
           .verifierCreationFailed(let reason),
           .signatureInvalid(let reason),
           .unsupportedAlgorithm(let reason):
        throw WRPRCError.malformedRegistrationCertificate(cause: reason)
      }
    }

    // Validate time claims (both iat and exp OPTIONAL; no string-sub check).
    let payloadJSON = try decodePayload(verifiedJWS)
    try validateTimeClaims(payloadJSON)

    // Compute offered credential configurations for this credential offer.
    let offeredConfigurations = issuerMetadata.credentialsSupported
      .filter { credentialOffer.credentialConfigurationIdentifiers.contains($0.key) }

    guard let wrpac = issuerMetadata.wrpac else {
      throw WRPRCError.missingWrpac
    }

    // Invoke the consumer-supplied policy validator.
    let authorization = await policy.authorize(wrpac, payloadJSON, offeredConfigurations)

    // Route the outcome.
    switch authorization {
    case .granted(let warnings):
      return warnings
    case .notGranted(let error):
      throw WRPRCError.policyNotMet(error)
    }
  }

  // MARK: - Helpers
  private func assertLeafKeyIsAsymmetric(chain: [String]) throws {
    guard
      let leaf = chain.first,
      let key = SecCertificateHelper().publicKey(fromPem: leaf)
    else {
      throw WRPRCError.malformedRegistrationCertificate(
        cause: "Could not extract public key from WRPRC leaf certificate"
      )
    }

    switch key.keyAlgorithm() {
    case "RSA", "EC":
      return
    default:
      throw WRPRCError.malformedRegistrationCertificate(
        cause: "WRPRC signing key must be asymmetric (RSA or EC)"
      )
    }
  }

  /// Every base64 entry in the x5c chain must produce a valid `SecCertificate`.
  private func assertAllCertificatesParse(chain: [String]) throws {
    for pem in chain {
      let cleaned = pem
        .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
        .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
        .replacingOccurrences(of: "\n", with: "")
      guard let data = Data(base64Encoded: cleaned),
            SecCertificateCreateWithData(nil, data as CFData) != nil
      else {
        throw WRPRCError.malformedRegistrationCertificate(
          cause: "x5c contains an unparseable certificate entry"
        )
      }
    }
  }

  private func decodePayload(_ jws: JWS) throws -> JSON {
    do {
      return try JSON(data: jws.payload.data())
    } catch {
      throw WRPRCError.malformedRegistrationCertificate(
        cause: "WRPRC payload is not valid JSON"
      )
    }
  }

  private func validateTimeClaims(_ payload: JSON) throws {
    let now = Date().timeIntervalSince1970
    let skew = SignedJWTValidation.clockSkew

    let iat = payload["iat"].double
    let exp = payload["exp"].double

    // If iat is present, it must not be in the future beyond skew.
    if let iat, iat > now + skew {
      throw WRPRCError.malformedRegistrationCertificate(cause: "WRPRC 'iat' is in the future")
    }

    // If exp is present, it must not have expired beyond skew.
    if let exp {
      if exp < now - skew {
        throw WRPRCError.malformedRegistrationCertificate(cause: "WRPRC has expired")
      }
      // Cross-check only when both iat and exp are present.
      if let iat, iat > exp + skew {
        throw WRPRCError.malformedRegistrationCertificate(cause: "WRPRC 'iat' is after 'exp'")
      }
    }
  }
}
