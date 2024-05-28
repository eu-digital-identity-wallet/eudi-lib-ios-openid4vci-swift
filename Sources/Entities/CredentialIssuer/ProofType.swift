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

public enum ProofType: Codable {
  case jwt
  case cwt
  case ldpVp
  
  private enum CodingKeys: String, CodingKey {
    case rawValue
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    let rawValue = try container.decode(String.self)
    
    switch rawValue {
    case "JWT", "jwt":
      self = .jwt
    case "CWT", "cwt":
      self = .cwt
    case "LDP_VP", "ldp_vp":
      self = .ldpVp
    default:
      throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid proof type")
    }
  }
  
  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    
    switch self {
    case .jwt:
      try container.encode("JWT")
    case .cwt:
      try container.encode("CWT")
    case .ldpVp:
      try container.encode("LDP_VP")
    }
  }
  
  public init(type: String) throws {
    switch type {
    case "JWT", "jwt":
      self = .jwt
    case "CWT", "cwt":
      self = .cwt
    case "LDP_VP", "ldp_vp":
      self = .ldpVp
    default:
      throw ValidationError.error(reason: "Invalid proof type: \(type)")
    }
  }
}
