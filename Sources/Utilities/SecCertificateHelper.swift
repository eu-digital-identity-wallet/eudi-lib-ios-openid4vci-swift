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
  public func extractPublicKey(certificate: SecCertificate) -> SecKey? {
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
  
  public func extractPublicKeyAlgorithm(certificate: SecCertificate) -> String? {
    guard let publicKey = extractPublicKey(certificate: certificate) else {
      return nil
    }
    
    // Get key attributes
    guard let attributes = SecKeyCopyAttributes(publicKey) as? [String: Any] else {
      return nil
    }
    
    // Ensure we get a valid key type
    guard let keyType = attributes[kSecAttrKeyType as String] as? String else {
      return nil
    }
    
    // Match against known key types
    switch keyType {
    case kSecAttrKeyTypeRSA as CFString:
      return "RSA"
    case kSecAttrKeyTypeECSECPrimeRandom as CFString, kSecAttrKeyTypeEC as CFString:
      return "Elliptic Curve (EC)"
    default:
      return "Unknown Algorithm (\(keyType))"
    }
  }
  
  /// Creates a `SecCertificate` from a PEM-encoded string
  public static func createCertificate(fromPEM pemString: String) -> SecCertificateContainer? {
    guard let data = Data(base64Encoded: pemString
      .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
      .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
      .replacingOccurrences(of: "\n", with: "")) else {
      return nil
    }
    return .init(
      certificate: SecCertificateCreateWithData(nil, data as CFData)
    )
  }
  
  /// Validates a certificate chain using a given set of certificates
  public static func validateCertificateChain(certificates: [SecCertificateContainer]) -> Bool {
    var trust: SecTrust?
    let policy = SecPolicyCreateBasicX509()
    let result = SecTrustCreateWithCertificates(
      certificates.map { $0.certificate } as CFArray,
      policy,
      &trust
    )
    
    guard
      result == errSecSuccess,
      let trust = trust,
      let root = certificates.first
    else {
      return false
    }
    
    // Perform the certificate validation
    var trustResult: SecTrustResultType = .invalid
    let rootArray = [root] as CFArray
    SecTrustSetAnchorCertificates(trust, rootArray)
    _ = SecTrustEvaluate(trust, &trustResult)
    
    var error: CFError?
    SecTrustEvaluateWithError(trust, &error)
    
    // Check the result of the trust evaluation
    switch trustResult {
    case .unspecified, .proceed:
      return true
    case .recoverableTrustFailure:
      if let trustProperties = SecTrustCopyProperties(trust) as? [[String: Any]] {
        for property in trustProperties {
          print("Property: \(property)")
        }
      }
      return true
    default:
      return false
    }
  }
}
