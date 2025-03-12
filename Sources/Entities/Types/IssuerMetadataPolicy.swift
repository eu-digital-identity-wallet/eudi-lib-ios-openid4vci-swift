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

/// A protocol for verifying the trustworthiness of a certificate chain.
public protocol CertificateChainTrust: Sendable {
  
  /// Checks whether a given certificate chain is trusted and verified.
  ///
  /// - Parameter chain: An array of certificate strings representing the certificate chain.
  /// - Returns: `true` if the certificate chain is trusted and verified, otherwise `false`.
  func isTrustedAndVerified(chain: [String]) -> Bool
}

/// Defines how the issuer's trust is determined.
public enum IssuerTrust: Sendable {
  
  /// Trust is established using a public key contained in a JSON Web Key (JWK).
  ///
  /// - Parameter jwk: The JSON Web Key representing the public key.
  case byPublicKey(jwk: JWK)
  
  /// Trust is established using a certificate chain validation process.
  ///
  /// - Parameter certificateChainTrust: A `CertificateChainTrust` instance that verifies the certificate chain.
  case byCertificateChain(certificateChainTrust: CertificateChainTrust)
}

/// Specifies the policy for handling signed issuer metadata.
public enum IssuerMetadataPolicy: Sendable {
  
  /// Requires the issuer metadata to be signed, using a specified trust mechanism.
  ///
  /// - Parameter issuerTrust: The trust mechanism used to verify the signed metadata.
  case requireSigned(issuerTrust: IssuerTrust)
  
  /// Prefers signed issuer metadata when available, using a specified trust mechanism.
  ///
  /// - Parameter issuerTrust: The trust mechanism used to verify the signed metadata.
  case preferSigned(issuerTrust: IssuerTrust)
  
  /// Ignores any signing requirement for the issuer metadata.
  case ignoreSigned
}
