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

/// Wallet's policy concerning credential response encryption.
public enum CredentialResponseEncryptionPolicy: Sendable, Equatable {
  /// The wallet requires credential responses to be encrypted.
  ///
  /// Issuance fails with `CredentialIssuanceError.responseEncryptionRequiredByWalletButNotSupportedByIssuer`
  /// when the issuer does not advertise response encryption, and with
  /// `CredentialIssuanceError.responseEncryptionRequiredByWalletButSpecMissing` when no mutually
  /// supported algorithm / encryption method exists (or no key material could be generated).
  case required
  /// The wallet supports encrypted credential responses but also accepts plaintext responses
  /// whenever the issuer does not require encryption.
  case supported
}

extension ECCurveType {
  var keySizeInBits: Int {
    switch self {
    case .P256: 256
    case .P384: 384
    case .P521: 521
    }
  }
}

/// Elliptic-curve key configuration used when negotiating credential response encryption.
public struct EcConfig: Sendable {

  /// ECDH-ES algorithms the wallet can offer.
  public static let platformSupportedAlgorithms: [JWEAlgorithm] = JWEAlgorithm.Family.parse(.ECDH_ES).all()

  /// Curve of the ephemeral key pair generated for response encryption.
  public let ecKeyCurve: ECCurveType

  /// ECDH-ES algorithms the wallet is willing to offer, in no particular order.
  /// Must be a non-empty subset of `platformSupportedAlgorithms`.
  public let supportedJWEAlgorithms: [JWEAlgorithm]

  /// - Parameters:
  ///   - ecKeyCurve: Curve of the ephemeral key pair (default: `.P256`).
  ///   - supportedJWEAlgorithms: ECDH-ES algorithms the wallet is willing to offer (default: all platform supported).
  public init(
    ecKeyCurve: ECCurveType = .P256,
    supportedJWEAlgorithms: [JWEAlgorithm] = EcConfig.platformSupportedAlgorithms
  ) {
    EncryptionSupportConfig.validate(
      supportedJWEAlgorithms,
      against: EcConfig.platformSupportedAlgorithms,
      what: "EcConfig.supportedJWEAlgorithms"
    )
    self.ecKeyCurve = ecKeyCurve
    self.supportedJWEAlgorithms = supportedJWEAlgorithms
  }

  func supports(_ algorithm: JWEAlgorithm) -> Bool {
    supportedJWEAlgorithms.contains { $0.name == algorithm.name }
  }
}

/// RSA key configuration used when negotiating credential response encryption.
public struct RsaConfig: Sendable {

  /// RSA algorithms the wallet can offer.
  public static let platformSupportedAlgorithms: [JWEAlgorithm] = JWEAlgorithm.Family.parse(.RSA).all()

  /// Size of the generated RSA key pair.
  public let rcaKeySize: Int

  /// RSA algorithms the wallet is willing to offer, in no particular order.
  /// Must be a non-empty subset of `platformSupportedAlgorithms`.
  public let supportedJWEAlgorithms: [JWEAlgorithm]

  /// - Parameters:
  ///   - rcaKeySize: Size of the generated RSA key pair, at least 2048 (default: `2048`).
  ///   - supportedJWEAlgorithms: RSA algorithms the wallet is willing to offer (default: all platform supported).
  public init(
    rcaKeySize: Int = 2048,
    supportedJWEAlgorithms: [JWEAlgorithm] = RsaConfig.platformSupportedAlgorithms
  ) {
    precondition(rcaKeySize >= 2048, "RsaConfig.rcaKeySize must be at least 2048")
    EncryptionSupportConfig.validate(
      supportedJWEAlgorithms,
      against: RsaConfig.platformSupportedAlgorithms,
      what: "RsaConfig.supportedJWEAlgorithms"
    )
    self.rcaKeySize = rcaKeySize
    self.supportedJWEAlgorithms = supportedJWEAlgorithms
  }

  func supports(_ algorithm: JWEAlgorithm) -> Bool {
    supportedJWEAlgorithms.contains { $0.name == algorithm.name }
  }
}

/// Wallet-side configuration of credential request / response encryption.
///
/// The issuer advertises what it supports in its metadata (`credential_response_encryption`, `credential_request_encryption`);
/// this type describes what the wallet is willing to use. `Issuer` negotiates the intersection,
/// preserving the issuer's preference order.
public struct EncryptionSupportConfig: Sendable {

  /// Content encryption methods the platform (JOSESwift) can handle.
  public static let platformSupportedEncryptionMethods: [JOSEEncryptionMethod] =
    JOSEEncryptionMethod.supportedByPlatform.map { .init($0) }

  /// Default: response encryption is supported but not required,
  /// EC P-256 and RSA 2048 key material, every platform supported encryption method.
  public static let `default` = EncryptionSupportConfig()

  /// Whether the wallet requires encrypted credential responses.
  public let credentialResponseEncryptionPolicy: CredentialResponseEncryptionPolicy

  /// Elliptic-curve configuration. `nil` disables the ECDH-ES family entirely.
  public let ecConfig: EcConfig?

  /// RSA configuration. `nil` disables the RSA family entirely.
  public let rsaConfig: RsaConfig?

  /// Content encryption methods the wallet is willing to use, for both request and response encryption.
  /// Must be a non-empty subset of `platformSupportedEncryptionMethods`.
  public let supportedEncryptionMethods: [JOSEEncryptionMethod]

  /// All key-management algorithms the wallet is willing to use (EC first, then RSA).
  public var supportedEncryptionAlgorithms: [JWEAlgorithm] {
    (ecConfig?.supportedJWEAlgorithms ?? []) + (rsaConfig?.supportedJWEAlgorithms ?? [])
  }

  /// - Parameters:
  ///   - credentialResponseEncryptionPolicy: Whether the wallet requires encrypted responses (default: `.supported`).
  ///   - ecConfig: EC configuration, `nil` disables ECDH-ES (default: P-256, all ECDH-ES algorithms).
  ///   - rsaConfig: RSA configuration, `nil` disables RSA (default: 2048 bit, all RSA algorithms).
  ///   - supportedEncryptionMethods: Content encryption methods the wallet accepts (default: all platform supported).
  public init(
    credentialResponseEncryptionPolicy: CredentialResponseEncryptionPolicy = .supported,
    ecConfig: EcConfig? = EcConfig(),
    rsaConfig: RsaConfig? = RsaConfig(),
    supportedEncryptionMethods: [JOSEEncryptionMethod] = EncryptionSupportConfig.platformSupportedEncryptionMethods
  ) {
    Self.validate(
      supportedEncryptionMethods,
      against: Self.platformSupportedEncryptionMethods,
      what: "EncryptionSupportConfig.supportedEncryptionMethods"
    )
    if case .required = credentialResponseEncryptionPolicy {
      precondition(
        ecConfig != nil || rsaConfig != nil,
        "EncryptionSupportConfig: .required response encryption policy needs an EcConfig or an RsaConfig"
      )
    }
    self.credentialResponseEncryptionPolicy = credentialResponseEncryptionPolicy
    self.ecConfig = ecConfig
    self.rsaConfig = rsaConfig
    self.supportedEncryptionMethods = supportedEncryptionMethods
  }

  func supports(algorithm: JWEAlgorithm) -> Bool {
    supportedEncryptionAlgorithms.contains { $0.name == algorithm.name }
  }

  func supports(method: JOSEEncryptionMethod) -> Bool {
    supportedEncryptionMethods.contains { $0.name == method.name }
  }

  /// Programmer-error validation shared by the nested configs: non-empty, no duplicates,
  /// subset of what the platform supports. Compared by JOSE name.
  static func validate<T: JOSEAlgorithm>(_ values: [T], against platform: [T], what: String) {
    precondition(!values.isEmpty, "\(what) must not be empty")
    let names = values.map(\.name)
    precondition(Set(names).count == names.count, "\(what) contains duplicate values")
    let platformNames = Set(platform.map(\.name))
    let unsupported = names.filter { !platformNames.contains($0) }
    precondition(
      unsupported.isEmpty,
      "\(what) contains values not supported by the platform: \(unsupported.joined(separator: ", "))"
    )
  }
}
