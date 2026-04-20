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

@testable import OpenID4VCI

extension SecCertificateHelper {
  
  /// Creates a `SecCertificate` from a PEM-encoded string
  static func createCertificate(fromPEM pemString: String) -> SecCertificateContainer? {
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
  static func validateCertificateChain(certificates: [SecCertificateContainer]) -> Bool {
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
  
  func extractPublicKeyAlgorithm(certificate: SecCertificate) -> String? {
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
}

