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
  
  init(string: String, validate: Bool = true) throws {
    if validate {
      if let queryItems = URLComponents(string: string)?.queryItems,
         queryItems.count > 0 {
        throw CredentialError.genericError
      }
    }
    
    if let validURL = URL(string: string) {
      self.url = validURL
      
      if self.url.fragment != nil {
       throw CredentialError.genericError
     }
    } else {
      throw CredentialError.genericError
    }
  }
}
