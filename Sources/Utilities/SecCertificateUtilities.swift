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

public final class SecCertificateSendable: @unchecked Sendable {
  public let certificate: SecCertificate?

  init(certificate: SecCertificate?) {
    self.certificate = certificate
  }
}

public struct SecCertificateUtilities: Sendable {
  
  /// Extracts the public key from a PEM-encoded certificate as `SecKey`
  public static func publicKey(fromPem pemString: String) -> SecKey? {
    // Remove PEM headers and footers
    let cleanedPem = pemString
      .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
      .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
      .replacingOccurrences(of: "\n", with: "")
    
    // Convert Base64 PEM to Data
    guard let certData = Data(base64Encoded: cleanedPem) else {
      print("Failed to decode Base64 certificate")
      return nil
    }
    
    // Create SecCertificate
    guard let certificate = SecCertificateCreateWithData(nil, certData as CFData) else {
      print("Failed to create certificate")
      return nil
    }
    
    return extractPublicKey(certificate: certificate)
  }
  
  /// Extracts the public key (`SecKey`) from a `SecCertificate`
  public static func extractPublicKey(certificate: SecCertificate) -> SecKey? {
    var trust: SecTrust?
    let policy = SecPolicyCreateBasicX509()
    
    // Create trust
    if SecTrustCreateWithCertificates(certificate, policy, &trust) != errSecSuccess {
      print("Failed to create trust")
      return nil
    }
    
    guard let trust = trust else { return nil }
    
    var result: SecTrustResultType = .invalid
    if SecTrustEvaluate(trust, &result) != errSecSuccess {
      print("Failed to evaluate trust")
      return nil
    }
    
    // Extract public key
    guard let publicKey = SecTrustCopyKey(trust) else {
      print("Failed to extract public key")
      return nil
    }
    
    return publicKey
  }
  
  public static func extractPublicKeyAlgorithm(certificate: SecCertificate) -> String? {
    guard let publicKey = extractPublicKey(certificate: certificate) else {
      print("Failed to extract public key")
      return nil
    }
    
    // Get key attributes
    guard let attributes = SecKeyCopyAttributes(publicKey) as? [String: Any] else {
      print("Failed to get key attributes")
      return nil
    }
    
    // Ensure we get a valid key type
    guard let keyType = attributes[kSecAttrKeyType as String] as? String else {
      print("Key type attribute not found")
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
  public static func createCertificate(fromPEM pemString: String) -> SecCertificateSendable? {
    guard let data = Data(base64Encoded: pemString
      .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
      .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
      .replacingOccurrences(of: "\n", with: "")) else {
      print("Failed to create Data from PEM string.")
      return nil
    }
    return .init(
      certificate: SecCertificateCreateWithData(nil, data as CFData)
    )
  }
  
  /// Validates a certificate chain using a given set of certificates
  public static func validateCertificateChain(certificates: [SecCertificateSendable]) -> Bool {
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
