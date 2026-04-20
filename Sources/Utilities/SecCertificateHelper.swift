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

/// A container for `SecCertificate` that marks it as `Sendable`.
///
/// `SecCertificate` itself is not `Sendable` because it is part of the
/// Security framework, which does not explicitly conform to Swift’s
/// concurrency model. This class acts as a wrapper to allow certificates
/// to be used safely in concurrent contexts.
///
/// - Note: The use of `@unchecked Sendable` assumes that `SecCertificate`
///   instances are immutable and safe to use across threads. Be cautious
///   when sharing instances in a concurrent environment.
public final class SecCertificateContainer: @unchecked Sendable {
  public let certificate: SecCertificate?

  init(certificate: SecCertificate?) {
    self.certificate = certificate
  }
}

public struct SecCertificateHelper: Sendable {
  
  public init() {
    
  }
  
  /// Extracts the public key from a PEM-encoded certificate as `SecKey`
  public func publicKey(fromPem pemString: String) -> SecKey? {
    // Remove PEM headers and footers
    let cleanedPem = pemString
      .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
      .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
      .replacingOccurrences(of: "\n", with: "")
    
    // Convert Base64 PEM to Data
    guard let certData = Data(base64Encoded: cleanedPem) else {
      return nil
    }
    
    // Create SecCertificate
    guard let certificate = SecCertificateCreateWithData(nil, certData as CFData) else {
      return nil
    }
    
    return extractPublicKey(certificate: certificate)
  }
  
  /// Extracts the public key (`SecKey`) from a `SecCertificate`
  internal func extractPublicKey(certificate: SecCertificate) -> SecKey? {
    var trust: SecTrust?
    let policy = SecPolicyCreateBasicX509()
    
    // Create trust
    if SecTrustCreateWithCertificates(certificate, policy, &trust) != errSecSuccess {
      return nil
    }
    
    guard let trust = trust else { return nil }
    
    var result: SecTrustResultType = .invalid
    if SecTrustEvaluate(trust, &result) != errSecSuccess {
      return nil
    }
    
    // Extract public key
    guard let publicKey = SecTrustCopyKey(trust) else {
      return nil
    }
    
    return publicKey
  }
}
