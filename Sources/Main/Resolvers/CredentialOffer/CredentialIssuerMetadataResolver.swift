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

public enum CredentialIssuerSource {
  case credentialIssuer(CredentialIssuerId)
}

public protocol CredentialIssuerMetadataType {
  /// The input type for resolving a type.
  associatedtype InputType

  /// The output type for resolved type. Must be Codable and Equatable.
  associatedtype OutputType: Decodable, Equatable

  /// The error type for resolving type. Must conform to the Error protocol.
  associatedtype ErrorType: Error

  /// Resolves type asynchronously.
  ///
  /// - Parameters:
  ///   - source: The input source for resolving data.
  /// - Returns: An asynchronous result containing the resolved data or an error.
  func resolve(
    source: InputType
  ) async -> Result<OutputType, ErrorType>
}

public actor CredentialIssuerMetadataResolver: CredentialIssuerMetadataType {
  
  private let fetcher: Fetcher<CredentialIssuerMetadata>
  
  public init(
    fetcher: Fetcher<CredentialIssuerMetadata> = Fetcher()
  ) {
    self.fetcher = fetcher
  }
  
  /// Resolves client metadata asynchronously.
  ///
  /// - Parameters:
  ///   - fetcher: The fetcher object responsible for fetching metadata. Default value is Fetcher<ClientMetaData>().
  ///   - source: The input source for resolving metadata.
  /// - Returns: An asynchronous result containing the resolved metadata or an error of type ResolvingError.
  public func resolve(
    source: CredentialIssuerSource
  ) async -> Result<CredentialIssuerMetadata, some Error> {
      switch source {
      case .credentialIssuer(let issuerId):
          let url = issuerId.url
              .appendingPathComponent(".well-known")
              .appendingPathComponent("openid-credential-issuer")
          return await fetcher.fetch(url: url)
      }
  }
}
