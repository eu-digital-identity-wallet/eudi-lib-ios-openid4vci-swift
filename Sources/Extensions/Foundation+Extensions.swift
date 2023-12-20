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

public extension URL {
  /// Extracts query parameters from the URL.
  var queryParameters: [String: String] {
    var parameters = [String: String]()
    
    if let components = URLComponents(url: self, resolvingAgainstBaseURL: false),
       let queryItems = components.queryItems {
      for item in queryItems {
        let name = item.name
        if let value = item.value {
          parameters[name] = value
        }
      }
    }
    return parameters
  }
  
  // Function to add query parameters to a URL
  func appendingQueryParameters(_ parameters: [String: String]) -> URL? {
    var components = URLComponents(url: self, resolvingAgainstBaseURL: false)
    
    var queryItems = components?.queryItems ?? []
    for (name, value) in parameters {
      queryItems.append(URLQueryItem(name: name, value: value))
    }
    
    components?.queryItems = queryItems
    return components?.url
  }
}
