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

public struct CredentialIssuerId: Codable, Equatable {
  public let url: URL
  
  public init(_ string: String) throws {
    if let queryItems = URLComponents(string: string)?.queryItems,
       queryItems.count > 0 {
      throw CredentialError.extraneousQueryComponents
    }
    
    guard
      let validURL = URL(string: string),
      validURL.scheme == "https",
      validURL.fragment == nil
    else {
      throw CredentialError.invalidScheme
    }
    
    self.url = validURL
  }
  
  private enum CodingKeys: String, CodingKey {
    case url = "credential_issuer"
  }
  
  // Implement the required init(from decoder:) method
  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    let urlString = try container.decode(String.self)
    try self.init(urlString)
  }
}
