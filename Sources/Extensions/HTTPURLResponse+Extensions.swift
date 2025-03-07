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

public extension HTTPURLResponse {
  
  private func valueForHeader(_ header: String) -> String? {
    let lowercasedHeader = header.lowercased()
    for (key, value) in allHeaderFields {
      if let keyString = key as? String, keyString.lowercased() == lowercasedHeader {
        return value as? String
      }
    }
    return nil
  }
  
  func containsDpopError() -> Bool {
    guard statusCode == HTTPStatusCode.unauthorized,
          let wwwAuth = valueForHeader("www-authenticate") else {
      return false
    }
    return wwwAuth.containsCaseInsensitive("DPoP") &&
           wwwAuth.containsCaseInsensitive("error=\"use_dpop_nonce\"")
  }
}

