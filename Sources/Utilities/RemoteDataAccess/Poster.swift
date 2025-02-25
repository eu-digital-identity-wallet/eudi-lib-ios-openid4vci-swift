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

// Result type for responses with headers
public struct ResponseWithHeaders<Response> {
  public let headers: [AnyHashable: Any]
  public let body: Response
  
  public init(headers: [AnyHashable: Any], body: Response) {
    self.headers = headers
    self.body = body
  }
}

public extension ResponseWithHeaders {
  func headerValue(forKey key: AnyHashable) -> Any? {
    return headers[key]
  }
}

public enum PostError: LocalizedError {
  case invalidUrl
  case networkError(Error)
  case response(GenericErrorResponse)
  case cannotParse(String)
  case serverError
  case useDpopNonce(Nonce)
  
  /**
   Provides a localized description of the post error.
   
   - Returns: A string describing the post error.
   */
  public var errorDescription: String? {
    switch self {
    case .invalidUrl:
      return "Invalid URL"
    case .networkError(let error):
      return "Network Error: \(error.localizedDescription)"
    case .response:
      return "Generic error response"
    case .cannotParse(let string):
      return "Could not parse: \(string)"
    case .serverError:
      return "Server error"
    case .useDpopNonce(let nonce):
      return "Use dPopp Nonce error: \(nonce)"
    }
  }
}

public protocol PostingType {
  
  var session: Networking { get set }
  
  /**
   Performs a POST request with the provided URLRequest.
   
   - Parameters:
   - request: The URLRequest to be used for the POST request.
   
   - Returns: A Result type with the response data or an error.
   */
  func post<Response: Codable>(request: URLRequest) async -> Result<ResponseWithHeaders<Response>, PostError>
  
  /**
   Performs a POST request with the provided URLRequest.
   
   - Parameters:
   - request: The URLRequest to be used for the POST request.
   
   - Returns: A Result type with a success boolean (based on status code) or an error.
   */
  func check(request: URLRequest) async -> Result<Bool, PostError>
}

public struct Poster: PostingType {
  
  public var session: Networking
  
  /**
   Initializes a Poster instance.
   */
  public init(
    session: Networking = URLSession.shared
  ) {
    self.session = session
  }
  
  /**
   Performs a POST request with the provided URLRequest.
   
   - Parameters:
   - request: The URLRequest to be used for the POST request.
   
   - Returns: A Result type with the response data or an error.
   */
  public func post<Response: Codable>(request: URLRequest) async -> Result<ResponseWithHeaders<Response>, PostError> {
    do {
      let (data, response) = try await self.session.data(for: request)
      let httpResponse = (response as? HTTPURLResponse)
      let statusCode = httpResponse?.statusCode ?? 0
      let headers = httpResponse?.allHeaderFields ?? [:]
      
      if statusCode >= HTTPStatusCode.badRequest && statusCode < HTTPStatusCode.internalServerError {
        if let httpResponse,
           httpResponse.containsDpopError(),
           let dPopNonce = headers.value(forCaseInsensitiveKey: Constants.DPOP_NONCE_HEADER) as? String {
          return .failure(
            .useDpopNonce(
              .init(
                value: dPopNonce
              )
            )
          )
        } else {
          let object = try JSONDecoder().decode(GenericErrorResponse.self, from: data)
          if object.error == Constants.USE_DPOP_NONCE,
             let dPopNonce = headers.value(forCaseInsensitiveKey: Constants.DPOP_NONCE_HEADER) as? String {
            return .failure(
              .useDpopNonce(
                .init(
                  value: dPopNonce
                )
              )
            )
          }
          return .failure(.response(object))
        }
        
      } else if statusCode >= HTTPStatusCode.internalServerError {
        return .failure(.serverError)
      }
      
      do {
        let object = try JSONDecoder().decode(Response.self, from: data)
        return .success(
          .init(
            headers: headers,
            body: object
          )
        )
      } catch {
        if statusCode == HTTPStatusCode.ok, let string = String(data: data, encoding: .utf8) {
          return .failure(.cannotParse(string))
        } else {
          return .failure(.networkError(error))
        }
      }
      
    } catch let error as NSError {
      return .failure(.networkError(error))
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
      let (_, response) = try await self.session.data(for: request)
      let httpResponse = (response as? HTTPURLResponse)
      
      return .success(httpResponse?.statusCode.isWithinRange(
        HTTPStatusCode.ok...HTTPStatusCode.imUsed
      ) ?? false)
    } catch let error as NSError {
      return .failure(.networkError(error))
    } catch {
      return .failure(.networkError(error))
    }
  }
}
