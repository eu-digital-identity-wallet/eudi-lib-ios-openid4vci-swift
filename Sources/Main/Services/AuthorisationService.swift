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
import JOSESwift
import SwiftyJSON

public enum JWEBuilderError: Error {
  case unsupportedKeyType
  case unsupportedAlgorithm
  case unsupportedEncryptionMethod
  case unsupportedCurve
  case invalidRecipientKey
  case encrypterInitFailed
}

/// A protocol for an authorization service.
public protocol AuthorisationServiceType: Sendable {
  /// Posts a response and returns a generic result.
  func formPost<T: Codable & Sendable, U: Codable & Sendable>(
    poster: PostingType,
    url: URL,
    request: T
  ) async throws -> ResponseWithHeaders<U>
  
  func formPost<T: Codable & Sendable, U: Codable & Sendable>(
    poster: PostingType,
    url: URL,
    request: T,
    headers: [String: String]
  ) async throws -> ResponseWithHeaders<U>
  
  func formPost<U: Codable & Sendable>(
    poster: PostingType,
    url: URL,
    headers: [String: String],
    parameters: [String: String]
  ) async throws -> ResponseWithHeaders<U>
  
  func formPost<U: Codable & Sendable>(
    poster: PostingType,
    url: URL,
    headers: [String: String],
    body: [String: any Sendable],
    encryptionSpec: EncryptionSpec?
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
    body: [String: any Sendable],
    encryptionSpec: EncryptionSpec?
  ) async throws -> ResponseWithHeaders<U> {
    
    let post: FormPost = if let encryptionSpec {
      try .init(
        url: url,
        contentType: .jwt,
        additionalHeaders: headers,
        formData: ["jwt": makeJWE(
          spec: encryptionSpec,
          body: body
        ).compactSerializedData]
      )
    } else {
      try .init(
        url: url,
        contentType: .json,
        additionalHeaders: headers,
        formData: body
      )
    }
    
    let result: Result<ResponseWithHeaders<U>, PostError> = await poster.post(request: post.urlRequest)
    return try result.get()
  }
}

private extension AuthorisationService {
  
  /// Build a JWE from an EncryptionSpec and a dictionary payload.
  func makeJWE(
      spec: EncryptionSpec,
      body: [String: any Sendable]
  ) throws -> JWE {
    
    /// Serialize the body into JSON `Data`
    let data = try body.toData()
    let payload = Payload(data)

    /// Build JWE header
    var headerParams: [String: Any] = [
      EncryptionKey.alg.rawValue: spec.algorithm.name,
      EncryptionKey.enc.rawValue: spec.encryptionMethod.name,
      EncryptionKey.type.rawValue: EncryptionKey.JWT.rawValue
    ]

    /// If the spec's key is a JWK, embed it in the header.
    if let jwkDict = try? spec.recipientKey.toDictionary() {
      headerParams["jwk"] = jwkDict
    }

    let header = try JWEHeader(parameters: headerParams)

    /// Build encrypter
    /// This example assumes EC keys
    guard spec.recipientKey.keyType == .EC else {
      throw JWEBuilderError.unsupportedKeyType
    }
    
    guard
      let keyManagementAlg = KeyManagementAlgorithm(
        algorithm: spec.algorithm
      ),
      let contentEncryptionAlg = ContentEncryptionAlgorithm(
        encryptionMethod: spec.encryptionMethod
      ),
      let encrypter: Encrypter = .init(
        keyManagementAlgorithm: keyManagementAlg,
        contentEncryptionAlgorithm: contentEncryptionAlg,
        encryptionKey: spec.recipientKey
      )
    else {
      throw JWEBuilderError.encrypterInitFailed
    }
    
    return try .init(
      header: header,
      payload: payload,
      encrypter: encrypter
    )
  }
}
