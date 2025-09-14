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

/// Compression algorithm name
///
/// Encodes/decodes as a single string, e.g. `"DEF"`.
public struct CompressionAlgorithm: RawRepresentable, Codable, Hashable, Sendable,
                                    ExpressibleByStringLiteral, CustomStringConvertible {
  
  /// Underlying algorithm name (case-sensitive).
  public let rawValue: String
  
  /// Create with an arbitrary name (e.g., "DEF", or any custom token).
  public init(rawValue: String) {
    precondition(!rawValue.isEmpty, "Compression algorithm name must not be empty")
    self.rawValue = rawValue
  }
  
  /// Convenience init
  public init(_ name: String) { self.init(rawValue: name) }
  
  /// String literal convenience: `let alg: CompressionAlgorithm = "DEF"`
  public init(stringLiteral value: StringLiteralType) {
    self.init(rawValue: value)
  }
  
  /// Standard DEFLATE per RFC 7516 ("zip":"DEF")
  public static let def = CompressionAlgorithm("DEF")
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    let value = try container.decode(String.self)
    self.init(rawValue: value)
  }
  
  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    try container.encode(rawValue)
  }
  
  public var description: String { rawValue }
}




//public struct CompressionAlgorithm: Decodable, Sendable {
//  public let name: String
//  
//  public init(name: String) {
//    self.name = name
//  }
//  
//  public init(from decoder: Decoder) throws {
//    let container = try decoder.singleValueContainer()
//    self.name = try container.decode(String.self)
//  }
//}
