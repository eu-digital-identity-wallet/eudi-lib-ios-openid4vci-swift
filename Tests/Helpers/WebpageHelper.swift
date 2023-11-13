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

class WebpageHelper {
  
  func downloadWebPage(url: URL) async -> Result<String?, Error> {
    do {
      let (data, _) = try await URLSession.shared.data(from: url)
      if let htmlString = String(data: data, encoding: .utf8) {
        return .success(htmlString)
      } else {
        return .success(nil)
      }
    } catch {
      return .success(nil)
    }
  }

  func extractFormFields(from htmlString: String) -> [String: String] {
    do {
      let doc = try SwiftSoup.parse(htmlString)
      let form = try doc.select("form").first()
      var formFields = [String: String]()
      
      for element in try form?.select("input") ?? .init() {
        let name = try element.attr("name")
        let value = try element.val()
        formFields[name] = value
      }
      
      return formFields
      
    } catch {
      print("Error parsing HTML: \(error)")
      return [:]
    }
  }

  func submitFormUsingBody(
    username: String,
    password: String,
    formFields: [String: String],
    actionURL: URL
  ) async throws {
    var request = URLRequest(url: actionURL)
    request.httpMethod = "POST"
    
    // Build the request body using the form fields
    var body = ""
    for (key, value) in formFields {
      body += "\(key)=\(value)&"
    }
    body += "fname=\(username)&lname=\(password)"
    request.httpBody = body.data(using: .utf8)
    
    let (data, _) = try await URLSession.shared.data(for: request)
    
    if let responseString = String(data: data, encoding: .utf8) {
      // Handle the response here
      print("Response: \(responseString)")
    } else {
      print("Invalid response data.")
    }
  }

  func submitFormDataUsingQuery(
    username: String,
    password: String,
    formFields: [String: String],
    actionURL: URL
  ) async throws {
    var components = URLComponents(url: actionURL, resolvingAgainstBaseURL: false)!
    components.queryItems = formFields.compactMap { field in
      if field.key == "fname" {
        return URLQueryItem(name: field.key, value: username)
      } else if field.key == "lname" {
        return URLQueryItem(name: field.key, value: password)
      }
      return nil
    }
    
    guard let finalURL = components.url else {
      throw NSError(domain: "Invalid URL", code: 0, userInfo: nil)
    }
    
    var request = URLRequest(url: finalURL)
    request.httpMethod = "POST"
    
    let (data, _) = try await URLSession.shared.data(for: request)
    
    if let responseString = String(data: data, encoding: .utf8) {
      print("Response: \(responseString)")
    } else {
      print("Invalid response data.")
    }
  }

  func submit(
    formUrl: URL,
    actionUrl: URL
  ) async throws {
    
    if let htmlString = try await downloadWebPage(url: formUrl).get() {
      let formFields = extractFormFields(from: htmlString)
      let username = "username"
      let password = "password"
      
      try await submitFormDataUsingQuery(
        username: username,
        password: password,
        formFields: formFields,
        actionURL: actionUrl
      )
    }
  }
}
