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
import SwiftyJSON

/// An implementation of form POST ``Request``.
public struct FormPost: Request {
  public typealias Response = AuthorizationRequest

  // MARK: - Request
  public var method: HTTPMethod { .POST }
  public let url: URL
  public let additionalHeaders: [String: String]
  public let body: Data?

  /// The URL request representation of the DirectPost.
  var urlRequest: URLRequest {
    var request = URLRequest(url: url)
    request.httpMethod = method.rawValue
    request.httpBody = body

    // request.allHTTPHeaderFields = additionalHeaders
    for (key, value) in additionalHeaders {
      request.addValue(value, forHTTPHeaderField: key)
    }

    return request
  }

  init(
    url: URL,
    /// The content type of the request body.
    contentType: ContentType,
    additionalHeaders: [String: String] = [:],
    /// The form data for the request body.
    formData: [String: Any]
  ) {
    self.additionalHeaders = [
      ContentType.key: contentType.rawValue
    ].merging(additionalHeaders) { (_, new) in new }
    self.url = url
    switch contentType {
    case .form:
      self.body = FormURLEncoded.body(from: formData)
    case .json:
      self.body = try? JSON(formData).rawData()
    }
  }

}

private extension FormPost {
  enum FormURLEncoded {
    static func body(from formData: [String: Any]) -> Data? {
      guard !formData.isEmpty else {
        return nil
      }
      var components: [String] = []
      for (key, value) in formData {
        if let encodedKey = encoded(string: key),
           let encodedValue = encoded(any: value) {
          components.append("\(encodedKey)=\(encodedValue)")
        }
      }
      return components.joined(separator: "&").data(using: .ascii)
    }

    static func encoded(string: String) -> String? {
      // See HTML 4.01 Specification, 17.13.4 Form content types: https://www.w3.org/TR/html401/interact/forms.html#h-17.13.4
      string
      // Unify line breaks to CR+LF
        .replacingOccurrences(of: "\r\n", with: "\n")
        .replacingOccurrences(of: "\n", with: "\r\n")
      // Percent-encode all reserved characters
        .addingPercentEncoding(withAllowedCharacters: FormURLEncoded.allowedCharacters)?
      // Convert spaces to '+' characters
        .replacingOccurrences(of: " ", with: "+")
    }

    static func encoded(any: Any?) -> String? {
      return switch any {
      case nil: ""
      case let string as String: encoded(string: string)
      case let int as Int: encoded(string: String(int))
      case let number as any Numeric: encoded(string: "\(number)")
      default: nil
      }
    }

    static let allowedCharacters: CharacterSet = {
      var allowedCharacterSet = CharacterSet.alphanumerics
      allowedCharacterSet.insert(charactersIn: "-._* ")
      return allowedCharacterSet
    }()
  }
}
