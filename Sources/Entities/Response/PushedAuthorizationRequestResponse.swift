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
import Foundation

public enum PushedAuthorizationRequestResponse: Codable {
  case success(requestURI: String, expiresIn: Int)
  case failure(error: String, errorDescription: String?)
  
  enum CodingKeys: String, CodingKey {
    case requestURI = "request_uri"
    case expiresIn = "expires_in"
    case error
    case errorDescription = "error_description"
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    
    if let requestURI = try? container.decode(String.self, forKey: .requestURI),
       let expiresIn = try? container.decode(Int.self, forKey: .expiresIn) {
      self = .success(requestURI: requestURI, expiresIn: expiresIn)
    } else if let error = try? container.decode(String.self, forKey: .error),
              let errorDescription = try? container.decode(String.self, forKey: .errorDescription) {
      self = .failure(error: error, errorDescription: errorDescription)
    } else {
      throw DecodingError.dataCorrupted(
        DecodingError.Context(
          codingPath: decoder.codingPath,
          debugDescription: "Invalid response format"
        )
      )
    }
  }
  
  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    
    switch self {
    case let .success(requestURI, expiresIn):
      try container.encode(requestURI, forKey: .requestURI)
      try container.encode(expiresIn, forKey: .expiresIn)
    case let .failure(error, errorDescription):
      try container.encode(error, forKey: .error)
      try container.encode(errorDescription, forKey: .errorDescription)
    }
  }
}
