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

extension SecKey {
  /// Returns the algorithm type of a `SecKey` (e.g., RSA, EC)
  func keyAlgorithm() -> String? {
    // Get key attributes
    guard let attributes = SecKeyCopyAttributes(self) as? [String: Any] else {
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
      return "EC"
    default:
      return nil
    }
  }
}
