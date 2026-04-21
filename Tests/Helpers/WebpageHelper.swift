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
import SwiftSoup

@testable import OpenID4VCI

class WebpageHelper {
  
  let session: Networking
  
  init(_ session: Networking) {
    self.session = session
  }
  
  func submit(
    formUrl: URL,
    username: String,
    password: String
  ) async throws -> (String, String) {
    let htmlString = try await downloadWebPage(url: formUrl)
    let actionUrl = try extractAction(from: htmlString)
       
    return try await submitFormUsingBody(
      username: username,
      password: password,
      actionURL: actionUrl
    )
  }
  
  private func downloadWebPage(url: URL) async throws -> String {
    let (data, _) = try await session.data(from: url)
    guard let htmlString = String(data: data, encoding: .utf8) else {
      throw ValidationError.error(reason: "Failed to parse response data as UTF-8")
    }
    
    return htmlString
  }
  
  private func extractAction(from htmlString: String) throws -> URL {
      let doc = try SwiftSoup.parse(htmlString)
      let form = try doc.getElementById("kc-form-login")
      guard let action = try? form?.attr("action"),
            let url = URL(string: action) else {
        throw ValidationError.error(reason: "Failed to extract form action URL from htmlString: \(htmlString)")
      }
      
      return url
  }
  
  private func submitFormUsingBody(
    username: String,
    password: String,
    actionURL: URL
  ) async throws -> (String, String) {
    var request = URLRequest(url: actionURL)
    request.httpMethod = "POST"
    
    var body = ""
    body += "username=\(username)&password=\(password)"
    request.httpBody = body.data(using: .utf8)
    
    let (_, response) = try await session.data(for: request)
    
    guard let httpResponse = response as? HTTPURLResponse else {
      throw ValidationError.error(reason: "Invalid response")
    }
    
    let redirectUrl = httpResponse.url
    
    let code = try extractValue(
      url: redirectUrl,
      forKey: "code"
    )
    
    let state = try extractValue(
      url: redirectUrl,
      forKey: "state"
    )
    
    return (code, state)
  }
  
  private func extractValue(
    url: URL?,
    forKey key: String
  ) throws -> String {
    guard let url = url,
          let queryItems = URLComponents(url: url, resolvingAgainstBaseURL: true)?.queryItems,
          let queryItem = queryItems.first(where: { $0.name == key }),
          let value = queryItem.value else {
      throw ValidationError.error(reason: "Key \(key) not found in URL query: \(url?.absoluteString ?? "")")
    }
    
    return value
  }
}
