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

/// A protocol for an authorization service.
public protocol AuthorisationServiceType {
  /// Posts a response and returns a generic result.
  func formPost<T: Codable, U: Codable>(
    poster: PostingType,
    url: URL,
    request: T
  ) async throws -> ResponseWithHeaders<U>
  
  func formPost<T: Codable, U: Codable>(
    poster: PostingType,
    url: URL,
    request: T,
    headers: [String: String]
  ) async throws -> ResponseWithHeaders<U>
  
  func formPost<U: Codable>(
    poster: PostingType,
    url: URL,
    headers: [String: String],
    parameters: [String: String]
  ) async throws -> ResponseWithHeaders<U>
  
  func formPost<U: Codable>(
    poster: PostingType,
    url: URL,
    headers: [String: String],
    body: [String: Any]
  ) async throws -> ResponseWithHeaders<U>
}

/// An implementation of the `AuthorisationServiceType` protocol.
public actor AuthorisationService: AuthorisationServiceType {
  
  public init() { }
  
  /// Posts a response and returns a generic result.
  public func formPost<T: Codable, U: Codable>(
    poster: PostingType = Poster(),
    url: URL,
    request: T
  ) async throws -> ResponseWithHeaders<U> {
    let post = try FormPost(
      url: url,
      contentType: .form,
      formData: try request.toDictionary()
    )
    
    let result: Result<ResponseWithHeaders<U>, PostError> = await poster.post(request: post.urlRequest)
    return try result.get()
  }
  
  public func formPost<T: Codable, U: Codable>(
    poster: PostingType,
    url: URL,
    request: T,
    headers: [String: String]
  ) async throws -> ResponseWithHeaders<U> {
    let post = try FormPost(
      url: url,
      contentType: .form,
      additionalHeaders: headers,
      formData: try request.toDictionary()
    )
    
    let result: Result<ResponseWithHeaders<U>, PostError> = await poster.post(request: post.urlRequest)
    return try result.get()
  }
  
  public func formPost<U: Codable>(
    poster: PostingType,
    url: URL,
    headers: [String: String] = [:],
    parameters: [String: String]
  ) async throws -> ResponseWithHeaders<U> {
    let post = try FormPost(
      url: url,
      contentType: .form,
      additionalHeaders: headers,
      formData: parameters
    )
    
    let result: Result<ResponseWithHeaders<U>, PostError> = await poster.post(request: post.urlRequest)
    return try result.get()
  }
  
  public func formPost<U: Codable>(
    poster: PostingType,
    url: URL,
    headers: [String: String],
    body: [String: Any]
  ) async throws -> ResponseWithHeaders<U> {
    let post = try FormPost(
      url: url,
      contentType: .json,
      additionalHeaders: headers,
      formData: body
    )
    
    let result: Result<ResponseWithHeaders<U>, PostError> = await poster.post(request: post.urlRequest)
    return try result.get()
  }
}
