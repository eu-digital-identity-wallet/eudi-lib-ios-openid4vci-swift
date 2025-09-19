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

public enum FetchError: LocalizedError {
  case invalidUrl
  case networkError(Error)
  case invalidResponse
  case decodingError(Error)
  case invalidStatusCode(URL, Int)

  /**
   Provides a localized description of the fetch error.

   - Returns: A string describing the fetch error.
   */
  public var errorDescription: String? {
    switch self {
    case .invalidUrl:
      return ".invalidUrl"
    case .networkError(let error):
      return ".networkError \(error.localizedDescription)"
    case .invalidResponse:
      return ".invalidResponse"
    case .decodingError(let error):
      return ".decodingError \(error.localizedDescription)"
    case .invalidStatusCode(let code, let url):
      return ".invalidStatusCode \(code) \(url)"
    }
  }
}

/**
 A structure that contains both the response data and HTTP headers.
 */
public struct RawFetchResponse: Decodable, Sendable {
  public let data: Data
  public let headers: [String: String]
  
  public init(
    data: Data,
    headers: [String: String]
  ) {
    self.data = data
    self.headers = headers
  }
}

public protocol RawFetching: Sendable {
  /// Fetches raw data with headers from the provided URL
  /// - Parameters:
  ///   - url: The URL from which to fetch the data
  ///   - additionalHeaders: Additional headers to include in the request
  /// - Returns: A Result containing RawFetchResponse or FetchError
  func fetchRawWithHeaders(
    url: URL,
    additionalHeaders: [String: String]
  ) async -> Result<RawFetchResponse, FetchError>
}

public protocol Fetching: Sendable {
  var session: Networking { get set }

  associatedtype Element: Decodable

  /**
    Fetches data from the provided URL.

    - Parameters:
       - session: The URLSession to use for fetching the data.
       - url: The URL from which to fetch the data.

    - Returns: A `Result` type with the fetched data or an error.
   */
  func fetch(url: URL) async -> Result<Element, FetchError>
}

public struct Fetcher<Element: Decodable>: Fetching, RawFetching {

  public var session: Networking

  /**
   Initializes a Fetcher instance.
   */
  public init(
    session: Networking = URLSession.shared
  ) {
    self.session = session
  }

  /**
   Fetches data from the provided URL.

   - Parameters:
      - url: The URL from which to fetch the data.

   - Returns: A Result type with the fetched data or an error.
   */
  public func fetch(url: URL) async -> Result<Element, FetchError> {
    do {
      let (data, response) = try await self.session.data(from: url)

      let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
      if !statusCode.isWithinRange(HTTPStatusCode.ok...HTTPStatusCode.imUsed) {
        throw FetchError.invalidStatusCode(url, statusCode)
      }
      let object = try JSONDecoder().decode(Element.self, from: data)

      return .success(object)
    } catch let error as NSError {
      if error.domain == NSURLErrorDomain {
        return .failure(.networkError(error))
      } else {
        return .failure(.decodingError(error))
      }
    } catch {
      return .failure(.decodingError(error))
    }
  }

  public func fetchString(url: URL) async throws -> Result<String, FetchError> {
    do {
      let (data, response) = try await self.session.data(from: url)

      let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
      if !statusCode.isWithinRange(HTTPStatusCode.ok...HTTPStatusCode.imUsed) {
        throw FetchError.invalidStatusCode(url, statusCode)
      }

      if let string = String(data: data, encoding: .utf8) {
        return .success(string)

      } else {

        let error = NSError(
          domain: "com.networking",
          code: 0,
          userInfo: [NSLocalizedDescriptionKey: "Failed to convert data to string"]
        )

        return .failure(.decodingError(error))
      }
    }
  }
  
  public func fetchRawWithHeaders(
    url: URL,
    additionalHeaders: [String: String] = [:]
  ) async -> Result<RawFetchResponse, FetchError> {
    do {
      var request = URLRequest(url: url)
      
      for (key, value) in additionalHeaders {
        request.setValue(value, forHTTPHeaderField: key)
      }
      
      let (data, response) = try await self.session.data(for: request)
      
      let httpResponse = response as? HTTPURLResponse
      let statusCode = httpResponse?.statusCode ?? 0
      
      if !statusCode.isWithinRange(HTTPStatusCode.ok...HTTPStatusCode.imUsed) {
        throw FetchError.invalidStatusCode(url, statusCode)
      }
      
      // Extract headers from the HTTP response
      let headers = httpResponse?.allHeaderFields.compactMapValues { value in
        value as? String
      }.reduce(into: [String: String]()) { result, element in
        result[element.key as? String ?? ""] = element.value
      } ?? [:]
      
      let fetchResponse = RawFetchResponse(
        data: data,
        headers: headers
      )
      
      return .success(fetchResponse)
    } catch let error as NSError {
      if error.domain == NSURLErrorDomain {
        return .failure(.networkError(error))
      } else {
        return .failure(.networkError(error))
      }
    } catch {
      return .failure(.networkError(error))
    }
  }
}
