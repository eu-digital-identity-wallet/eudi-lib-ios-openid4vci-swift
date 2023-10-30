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

public enum PostError: Error {
  case invalidUrl
  case networkError(Error)

  /**
   Provides a localized description of the post error.

   - Returns: A string describing the post error.
   */
  public var localizedDescription: String {
    switch self {
    case .invalidUrl:
      return "Invalid URL"
    case .networkError(let error):
      return "Network Error: \(error.localizedDescription)"
    }
  }
}

public protocol Posting {
  /**
   Performs a POST request with the provided URLRequest.

   - Parameters:
      - request: The URLRequest to be used for the POST request.

   - Returns: A Result type with the response data or an error.
   */
  func post<Response: Codable>(request: URLRequest) async -> Result<Response, PostError>

  /**
   Performs a POST request with the provided URLRequest.

   - Parameters:
      - request: The URLRequest to be used for the POST request.

   - Returns: A Result type with a success boolean (based on status code) or an error.
   */
  func check(request: URLRequest) async -> Result<Bool, PostError>
}

public struct Poster: Posting {
  /**
   Initializes a Poster instance.
   */
  public init() {}

  /**
   Performs a POST request with the provided URLRequest.

   - Parameters:
      - request: The URLRequest to be used for the POST request.

   - Returns: A Result type with the response data or an error.
   */
  public func post<Response: Codable>(request: URLRequest) async -> Result<Response, PostError> {
    do {
      let delegate = SelfSignedSessionDelegate()
      let configuration = URLSessionConfiguration.default
      let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
      let (data, _) = try await session.data(for: request)
      let object = try JSONDecoder().decode(Response.self, from: data)

      return .success(object)
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

  /**
   Performs a POST request with the provided URLRequest.

   - Parameters:
      - request: The URLRequest to be used for the POST request.

   - Returns: A Result type with a success boolean (based on status code) or an error.
   */
  public func check(request: URLRequest) async -> Result<Bool, PostError> {
    do {
      let delegate = SelfSignedSessionDelegate()
      let configuration = URLSessionConfiguration.default
      let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
      let (_, response) = try await session.data(for: request)
      
      print(response)
      
      return .success((response as? HTTPURLResponse)?.statusCode.isWithinRange(200...299) ?? false)
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
