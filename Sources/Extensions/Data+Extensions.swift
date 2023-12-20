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

extension Data {
  // Generates random data of the specified length
  static func randomData(length: Int) -> Data {
    var data = Data(count: length)
    _ = data.withUnsafeMutableBytes { mutableBytes in
      if let bytes = mutableBytes.bindMemory(to: UInt8.self).baseAddress {
        return SecRandomCopyBytes(kSecRandomDefault, length, bytes)
      }
      fatalError("Failed to generate random bytes")
    }
    return data
  }

  // Encodes the data as a base64 URL-safe string
  func base64URLEncodedString() -> String {
    var base64String = self.base64EncodedString()
    base64String = base64String.replacingOccurrences(of: "/", with: "_")
    base64String = base64String.replacingOccurrences(of: "+", with: "-")
    base64String = base64String.replacingOccurrences(of: "=", with: "")
    return base64String
  }
}
