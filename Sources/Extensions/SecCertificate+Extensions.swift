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

extension SecCertificate {
  /// Extracts the public key from a PEM-encoded certificate as `SecKey`
  static func publicKey(fromPem pemString: String) -> SecKey? {
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
    
    return certificate.extractPublicKey()
  }
  
  /// Extracts the public key (`SecKey`) from a `SecCertificate`
  func extractPublicKey() -> SecKey? {
    var trust: SecTrust?
    let policy = SecPolicyCreateBasicX509()
    
    // Create trust
    if SecTrustCreateWithCertificates(self, policy, &trust) != errSecSuccess {
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
  
  func extractPublicKeyAlgorithm() -> String? {
    guard let publicKey = extractPublicKey() else {
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
}
