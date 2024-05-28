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

public enum AuthorizationCodeURLError: Error {
  case missingQueryParameters
}

public struct GetAuthorizationCodeURL {
  public let url: URL
  
  public init(urlString: String) throws {
    guard let url = URL(string: urlString) else {
      throw ValidationError.invalidUrl(urlString)
    }
    
    guard url.scheme == "https" else {
      throw ValidationError.nonHttpsUrl(urlString)
    }
    
    let parameters = url.queryParameters
    guard
      parameters["\(Self.PARAM_CLIENT_ID)"] != nil
    else {
      throw AuthorizationCodeURLError.missingQueryParameters
    }
    
    self.url = url
  }
  
  public static let PARAM_CLIENT_ID = "client_id"
  public static let PARAM_REQUEST_URI = "request_uri"
  public static let PARAM_REQUEST_STATE = "state"
}
