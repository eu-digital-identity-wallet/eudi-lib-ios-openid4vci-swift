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

public enum Credential: Codable {
  case string(String)
  case json(JSON)
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    if let stringValue = try? container.decode(String.self) {
      self = .string(stringValue)
    } else if let jsonObject = try? container.decode(JSON.self) {
      self = .json(jsonObject)
    } else {
      throw DecodingError.typeMismatch(
        Credential.self,
        DecodingError.Context(
          codingPath: decoder.codingPath,
          debugDescription: "Invalid Credential Type"
        )
      )
    }
  }
  
  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    switch self {
    case .string(let value):
      try container.encode(value)
    case .json(let jsonValue):
      try container.encode(jsonValue)
    }
  }
}
