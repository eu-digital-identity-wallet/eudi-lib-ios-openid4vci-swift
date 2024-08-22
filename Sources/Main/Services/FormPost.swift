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
  ) throws {
    self.additionalHeaders = [
      ContentType.key: contentType.rawValue
    ].merging(additionalHeaders) { (_, new) in new }
    self.url = url
    switch contentType {
    case .form:
      self.body = try FormURLEncoder.body(from: formData)
    case .json:
      self.body = try JSON(formData).rawData()
    }
  }

}

extension FormPost {
  public enum FormURLEncodingError: Swift.Error {
    case unsupportedName(String)
    case unsupportedValue(Any?)
  }

  // application/x-www-form-urlencoded encoder
  private enum FormURLEncoder {
    static func body(from formData: [String: Any]) throws -> Data {
      var output = ""
      for (n, v) in formData {
        if !output.isEmpty {
          output.append("&")
        }
        if let collection = v as? [Any?] {
          for v in collection {
            if !output.isEmpty {
              output.append("&")
            }
            try append(to: &output, name: n, value: v)
          }
        } else {
          try append(to: &output, name: n, value: v)
        }
      }
      return output.data(using: .ascii)!
    }

    static func append(to: inout String, name: String, value: Any?) throws {
      guard let encodedName = encoded(string: name) else {
        throw FormURLEncodingError.unsupportedName(name)
      }
      guard let encodedValue = encoded(any: value) else {
        throw FormURLEncodingError.unsupportedValue(value)
      }
      to.append(encodedName)
      to.append("=")
      to.append(encodedValue)
    }

    static func encoded(string: String) -> String? {
      // See https://url.spec.whatwg.org/#application/x-www-form-urlencoded
      string
      // Percent-encode all characters that are non-ASCII and not in the allowed character set
        .addingPercentEncoding(withAllowedCharacters: FormURLEncoder.allowedCharacters)?
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
      // See https://url.spec.whatwg.org/#application-x-www-form-urlencoded-percent-encode-set
      // Include also the space character to enable its encoding to '+'
      var allowedCharacterSet = CharacterSet.alphanumerics
      allowedCharacterSet.insert(charactersIn: "*-._ ")
      return allowedCharacterSet
    }()
  }
}
