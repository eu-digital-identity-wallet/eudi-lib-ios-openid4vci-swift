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

public enum ProofType: Decodable {
  case jwt
  case ldpVp
  case unsupported
  
  private enum CodingKeys: String, CodingKey {
    case rawValue
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    let rawValue = try container.decode(String.self)
    
    switch rawValue {
    case "JWT", "jwt":
      self = .jwt
    case "LDP_VP", "ldp_vp":
      self = .ldpVp
    default:
      self = .unsupported
    }
  }
  
  public init(type: String) throws {
    switch type {
    case "JWT", "jwt":
      self = .jwt
    case "LDP_VP", "ldp_vp":
      self = .ldpVp
    default:
      self = .unsupported
    }
  }
}
