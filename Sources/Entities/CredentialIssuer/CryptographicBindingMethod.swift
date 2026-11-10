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

public enum CryptographicBindingMethod: Codable, Equatable, Sendable {
  case jwk
  case x5c
  case coseKey
  case mso
  case did(method: String)
  /// A method that this library does not know. OpenID4VCI 1.0 allows other values.
  case other(String)
  
  private enum CodingKeys: String, CodingKey {
    case method
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    let stringValue = try container.decode(String.self)
    
    switch stringValue {
    case "jwk":
      self = .jwk
    case "x5c":
      self = .x5c
    case "cose_key":
      self = .coseKey
    case "mso":
      self = .mso
    default:
      self = stringValue.hasPrefix("did") ? .did(method: stringValue) : .other(stringValue)
    }
  }
  
  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    switch self {
    case .jwk:
      try container.encode("jwk")
    case .x5c:
      try container.encode("x5c")
    case .coseKey:
      try container.encode("cose_key")
    case .mso:
      try container.encode("mso")
    case .did(let method), .other(let method):
      try container.encode(method)
    }
  }
  
  public init(method: String) throws {
    switch method {
    case "jwk":
      self = .jwk
    case "x5c":
      self = .x5c
    case "cose_key":
      self = .coseKey
    case "mso":
      self = .mso
    default:
      self = method.hasPrefix("did") ? .did(method: method) : .other(method)
    }
  }
}
