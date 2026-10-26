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

public struct NetworkFailure: Error, Equatable, Sendable {

  public enum FailureMethod: String, Equatable, Sendable {
    case GET
    case POST
  }

  public let stage: FailureMethod
  public let url: URL?
  public let statusCode: Int?
  public let responseBody: Data?
  public let underlying: (any Error)?

  public init(
    stage: FailureMethod,
    url: URL?,
    statusCode: Int? = nil,
    responseBody: Data? = nil,
    underlying: (any Error)? = nil
  ) {
    self.stage = stage
    self.url = url
    self.statusCode = statusCode
    self.responseBody = responseBody
    self.underlying = underlying
  }

  public var urlError: URLError? {
    underlying as? URLError
  }

  public var isServerResponse: Bool {
    statusCode != nil
  }

  public static func == (lhs: NetworkFailure, rhs: NetworkFailure) -> Bool {
    let lhsError = lhs.underlying.map { $0 as NSError }
    let rhsError = rhs.underlying.map { $0 as NSError }
    return lhs.stage == rhs.stage
      && lhs.url == rhs.url
      && lhs.statusCode == rhs.statusCode
      && lhsError?.domain == rhsError?.domain
      && lhsError?.code == rhsError?.code
  }
}

extension NetworkFailure {

  init(stage: FailureMethod, url: URL, fetchError: FetchError) {
    switch fetchError {
    case .networkError(let error):
      self.init(stage: stage, url: url, underlying: error)
    case .invalidStatusCode(let failedUrl, let code, let body):
      self.init(stage: stage, url: failedUrl, statusCode: code, responseBody: body)
    default:
      self.init(stage: stage, url: url, underlying: fetchError)
    }
  }

  init(stage: FailureMethod, url: URL?, postError: PostError) {
    switch postError {
    case .networkError(let error):
      self.init(stage: stage, url: url, underlying: error)
    case .requestError(let code, let error):
      self.init(stage: stage, url: url, statusCode: code, underlying: error)
    case .invalidStatusCode(let failedUrl, let code, let body):
      self.init(stage: stage, url: failedUrl ?? url, statusCode: code, responseBody: body)
    default:
      self.init(stage: stage, url: url, underlying: postError)
    }
  }
}

extension FetchError {

  var isNetworkFailure: Bool {
    switch self {
    case .networkError, .invalidStatusCode:
      return true
    default:
      return false
    }
  }
}
