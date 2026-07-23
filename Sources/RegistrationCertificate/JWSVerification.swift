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
@preconcurrency import JOSESwift

/// Errors raised by the shared `IssuerTrust.verify(jws:)` helper.
internal enum JWSVerificationError: Error, Sendable {
  /// The `CertificateChainTrust` rejected the certificate chain.
  case chainNotTrusted
  /// The `x5c` header was empty or its leaf certificate could not be parsed.
  case invalidCertificateChain(String)
  /// A JWS `Verifier` could not be constructed for the resolved key.
  case verifierCreationFailed(String)
  /// The JWS signature failed cryptographic verification.
  case signatureInvalid(String)
  /// The signing key uses an algorithm not supported by this helper.
  case unsupportedAlgorithm(String)
}

/// Clock skew (seconds) used across the library for validating `iat` / `exp` on
/// signed JWTs. Kept in a single place so metadata (WRPAC) and WRPRC use the
/// same tolerance.
internal enum SignedJWTValidation {
  static let clockSkew: TimeInterval = 300
}

internal extension IssuerTrust {

  /// Verifies the certificate chain trust and JWS signature. Only RS256 and
  /// ES256 are supported.
  @discardableResult
  func verify(jws: JWS) async throws -> JWS {
    guard case .byCertificateChain(let certificateChainTrust) = self else {
      throw JWSVerificationError.unsupportedAlgorithm(
        "IssuerTrust variant not supported for JWS verification"
      )
    }

    let chain = jws.header.x5c ?? []
    guard !chain.isEmpty else {
      throw JWSVerificationError.invalidCertificateChain("x5c header is missing or empty")
    }
    guard await certificateChainTrust.isValid(chain: chain) else {
      throw JWSVerificationError.chainNotTrusted
    }

    let utilities: SecCertificateHelper = .init()
    guard
      let first = chain.first,
      let key = utilities.publicKey(fromPem: first)
    else {
      throw JWSVerificationError.invalidCertificateChain("Failed to extract public key from leaf certificate")
    }

    let algorithm: SignatureAlgorithm? = switch key.keyAlgorithm() {
    case "RSA": .RS256
    case "EC": .ES256
    default: nil
    }

    guard
      let algorithm,
      let verifier: Verifier = .init(signatureAlgorithm: algorithm, key: key)
    else {
      throw JWSVerificationError.verifierCreationFailed("Failed to create verifier from leaf certificate")
    }

    do {
      return try jws.validate(using: verifier)
    } catch {
      throw JWSVerificationError.signatureInvalid(error.localizedDescription)
    }
  }
}
