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
  
  func resetURLSession() -> URLSession {
    // Create a new URLSessionConfiguration with a different URLCache
    let newCache = URLCache(memoryCapacity: 0, diskCapacity: 0, diskPath: nil)
    let newConfiguration = URLSessionConfiguration.default
    newConfiguration.urlCache = newCache
    
    // Create a new URLSession with the modified configuration
    let newSession = URLSession(configuration: newConfiguration)
    
    return newSession
  }
  
  func downloadWebPage(url: URL) async -> Result<String?, Error> {
    do {
      let (data, _) = try await resetURLSession().data(from: url)
      if let htmlString = String(data: data, encoding: .utf8) {
        return .success(htmlString)
      } else {
        return .success(nil)
      }
    } catch {
      return .success(nil)
    }
  }
  
  func extractAction(from htmlString: String) -> URL? {
    do {
      let doc = try SwiftSoup.parse(htmlString)
      let form = try doc.getElementById("kc-form-login")
      guard let action = try? form?.attr("action") else {
        return nil
      }
      return URL(string: action)
      
    } catch {
      print("Error parsing HTML: \(error)")
      return nil
    }
  }
  
  func submitFormUsingBody(
    username: String,
    password: String,
    actionURL: URL
  ) async throws -> String {
    var request = URLRequest(url: actionURL)
    request.httpMethod = "POST"
    
    var body = ""
    body += "username=\(username)&password=\(password)"
    request.httpBody = body.data(using: .utf8)
    
    let (_, response) = try await URLSession.shared.data(for: request)
    
    guard let httpResponse = response as? HTTPURLResponse else {
      throw ValidationError.error(reason: "Invalid response")
    }
    
    let redirectUrl = httpResponse.url
    
    return try extractValue(
      url: redirectUrl,
      forKey: "code"
    ) ?? {
      throw ValidationError.error(reason: "Invalid authorisation code")
    }()
  }
  
  func submit(
    formUrl: URL,
    username: String,
    password: String
  ) async throws -> String? {
    
    if let htmlString = try await downloadWebPage(url: formUrl).get(),
       let actionUrl = extractAction(from: htmlString) {
      return try await submitFormUsingBody(
        username: username,
        password: password,
        actionURL: actionUrl
      )
    }
    
    return nil
  }
  
  private func extractValue(
    url: URL?,
    forKey key: String
  ) -> String? {
    if let url = url,
       let queryItems = URLComponents(url: url, resolvingAgainstBaseURL: true)?.queryItems {
      
      // Find the query item with the specified key
      if let queryItem = queryItems.first(where: { $0.name == key }),
         let value = queryItem.value {
        return value
      }
    }
    return nil
  }
}
