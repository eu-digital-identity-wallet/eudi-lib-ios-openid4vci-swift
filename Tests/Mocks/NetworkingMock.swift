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
import XCTest

@testable import OpenID4VCI

final class NetworkingMock: Networking {

  let path: String
  let `extension`: String
  let statusCode: Int
  let headers: [String: String]

  init(
    path: String,
    `extension`: String,
    statusCode: Int = 200,
    headers: [String: String] = [:]
  ) {
    self.path = path
    self.extension = `extension`
    self.statusCode = statusCode
    self.headers = headers
  }

  func data(
    from url: URL
  ) async throws -> (Data, URLResponse) {
    let path = Bundle.module.path(forResource: self.path, ofType: self.extension)
    let url = URL(fileURLWithPath: path!)
    let data = try Data(contentsOf: url)
    let result = Result<Data, Error>.success(data)
    let response = HTTPURLResponse(
      url: .stub(),
      statusCode: statusCode,
      httpVersion: nil,
      headerFields: headers
    )
    return try (result.get(), response!)
  }

  func data(
    for request: URLRequest
  ) async throws -> (Data, URLResponse) {
    return try await data(from: URL(string: "https://www.example.com")!)
  }
}

/// A networking mock that routes different URL patterns to different resource files.
/// Useful for testing scenarios where multiple different endpoints need to return different data.
final class RoutingNetworkingMock: Networking {

  struct Route {
    let urlPattern: String
    let path: String
    let `extension`: String
    let statusCode: Int
    let headers: [String: String]

    init(
      urlPattern: String,
      path: String,
      extension: String,
      statusCode: Int = 200,
      headers: [String: String] = [:]
    ) {
      self.urlPattern = urlPattern
      self.path = path
      self.extension = `extension`
      self.statusCode = statusCode
      self.headers = headers
    }
  }

  let routes: [Route]
  let fallbackPath: String
  let fallbackExtension: String

  init(
    routes: [Route],
    fallbackPath: String = "test",
    fallbackExtension: String = "json"
  ) {
    self.routes = routes
    self.fallbackPath = fallbackPath
    self.fallbackExtension = fallbackExtension
  }

  func data(
    from url: URL
  ) async throws -> (Data, URLResponse) {
    let urlString = url.absoluteString

    // Find matching route
    let matchedRoute = routes.first { route in
      urlString.contains(route.urlPattern)
    }

    let resourcePath: String
    let resourceExtension: String
    let statusCode: Int
    let headers: [String: String]

    if let route = matchedRoute {
      resourcePath = route.path
      resourceExtension = route.extension
      statusCode = route.statusCode
      headers = route.headers
    } else {
      resourcePath = fallbackPath
      resourceExtension = fallbackExtension
      statusCode = 200
      headers = [:]
    }

    guard let filePath = Bundle.module.path(forResource: resourcePath, ofType: resourceExtension) else {
      throw NSError(domain: "NetworkingMock", code: 404, userInfo: [
        NSLocalizedDescriptionKey: "Resource not found: \(resourcePath).\(resourceExtension)"
      ])
    }

    let fileURL = URL(fileURLWithPath: filePath)
    let data = try Data(contentsOf: fileURL)
    let response = HTTPURLResponse(
      url: url,
      statusCode: statusCode,
      httpVersion: nil,
      headerFields: headers
    )!
    return (data, response)
  }

  func data(
    for request: URLRequest
  ) async throws -> (Data, URLResponse) {
    guard let url = request.url else {
      throw NSError(domain: "NetworkingMock", code: 400, userInfo: [
        NSLocalizedDescriptionKey: "Request has no URL"
      ])
    }
    return try await data(from: url)
  }
}
