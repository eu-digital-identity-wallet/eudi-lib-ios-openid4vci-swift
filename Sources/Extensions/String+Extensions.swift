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

public extension String {
  var base64urlEncode: String {
    let data = Data(self.utf8)
    let base64 = data.base64EncodedString()
    let base64url = base64
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
    return base64url
  }

  /// Loads the contents of a string file from the bundle associated with the Swift package.
  ///
  /// - Parameters:
  ///   - fileName: The name of the string file.
  ///   - fileExtension: The file extension of the string file.
  /// - Returns: The contents of the string file, or `nil` if it fails to load.
  static func loadStringFileFromBundle(named fileName: String, withExtension fileExtension: String) -> String? {
    let bundle = Bundle.module

    guard let fileURL = bundle.url(forResource: fileName, withExtension: fileExtension),
      let data = try? Data(contentsOf: fileURL),
      let string = String(data: data, encoding: .utf8) else {
      return nil
    }
    return string
  }
}
