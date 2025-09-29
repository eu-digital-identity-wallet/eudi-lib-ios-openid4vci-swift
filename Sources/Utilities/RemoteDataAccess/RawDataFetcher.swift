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

// MARK: - Raw Data Fetching Protocol
public protocol RawDataFetching: Sendable {
  func fetchRawWithHeaders(
    url: URL,
    additionalHeaders: [String: String]
  ) async -> Result<RawFetchResponse, FetchError>
}


public struct RawDataFetcher: RawDataFetching {
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
      return .failure(.networkError(error))
    }
  }
}

