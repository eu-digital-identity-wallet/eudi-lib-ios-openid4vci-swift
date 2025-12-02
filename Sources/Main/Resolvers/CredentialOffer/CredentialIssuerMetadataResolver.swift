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
@preconcurrency import JOSESwift

public enum CredentialIssuerSource: Sendable {
  case credentialIssuer(CredentialIssuerId)
}

public protocol CredentialIssuerMetadataType {
  /// The input type for resolving a type.
  associatedtype InputType: Sendable
  
  /// The output type for resolved type. Must be Codable and Equatable.
  associatedtype OutputType: Decodable, Equatable, Sendable
  
  /// The error type for resolving type. Must conform to the Error protocol.
  associatedtype ErrorType: Error
  
  /// Resolves type asynchronously.
  ///
  /// - Parameters:
  ///   - source: The input source for resolving data.
  /// - Returns: An asynchronous result containing the resolved data or an error.
  func resolve(
    source: InputType,
    policy: IssuerMetadataPolicy
  ) async throws -> Result<OutputType, ErrorType>
}

public actor CredentialIssuerMetadataResolver: CredentialIssuerMetadataType {
  
  private let fetcher: any MetadataFetching
  
  
  public init(
    fetcher: MetadataFetching = MetadataFetcher()
  ) {
    self.fetcher = fetcher
  }
  
  /// Resolves client metadata asynchronously.
  ///
  /// - Parameters:
  ///   - source: The input source for resolving metadata.
  ///   - policy: The issuer metadata policy
  /// - Returns: An asynchronous result containing the resolved metadata or an error of type ResolvingError.
  public func resolve(
    source: CredentialIssuerSource,
    policy: IssuerMetadataPolicy
  ) async throws -> Result<CredentialIssuerMetadata, CredentialIssuerMetadataError> {
    switch source {
    case .credentialIssuer(let issuerId):
      let wellKnownURL = try buildWellKnownCredentialIssuerURL(from: issuerId.url)
      
      return await fetcher.fetchMetadata(
        url: wellKnownURL,
        policy: policy,
        issuerId: issuerId
      )
    }
  }
}
      
extension CredentialIssuerMetadataResolver {
  func buildWellKnownCredentialIssuerURL(
    from issuerURL: URL
  ) throws -> URL {
    
    guard
      var components = URLComponents(url: issuerURL, resolvingAgainstBaseURL: false)
    else {
      throw FetchError.invalidUrl
    }
    
    let wellKnownPath = "/.well-known/openid-credential-issuer"
    if components.percentEncodedPath != "/" {
        components.percentEncodedPath = wellKnownPath + components.percentEncodedPath
    } else {
        components.percentEncodedPath = wellKnownPath
    }
    
    guard let wellKnownURL = components.url else {
      throw FetchError.invalidUrl
    }
    
    return wellKnownURL
  }
}
