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

// MARK: - Metadata Fetching Protocol
public protocol MetadataFetching: Sendable {
  func fetchMetadata(
    url: URL,
    policy: IssuerMetadataPolicy,
    issuerId: CredentialIssuerId
  ) async -> Result<CredentialIssuerMetadata, CredentialIssuerMetadataError>
}

public struct MetadataFetcher: MetadataFetching {
  private let rawFetcher: RawDataFetching
  private let processor: MetadataProcessing
  
  public init(
    rawFetcher: any RawDataFetching = RawDataFetcher(),
    processor: any MetadataProcessing = MetadataProcessor()
  ) {
    self.rawFetcher = rawFetcher
    self.processor = processor
  }
  
  public func fetchMetadata(
    url: URL,
    policy: IssuerMetadataPolicy,
    issuerId: CredentialIssuerId
  ) async -> Result<CredentialIssuerMetadata, CredentialIssuerMetadataError> {
    
    let acceptHeader = determineAcceptHeader(for: policy)
    let headers = ["Accept": acceptHeader]
    
    let rawResult = await rawFetcher.fetchRawWithHeaders(
      url: url,
      additionalHeaders: headers
    )
    
    switch rawResult {
    case .success(let rawResponse):
      do {
        let metadata = try await processor.processMetadata(
          rawResponse: rawResponse,
          policy: policy,
          issuerId: issuerId
        )
        return .success(metadata)
      } catch let error as CredentialIssuerMetadataError {
        return .failure(error)
      } catch {
        return .failure(CredentialIssuerMetadataError.nonParseableCredentialIssuerMetadata(cause: error))
      }
      
    case .failure(let fetchError):
      return .failure(CredentialIssuerMetadataError.unableToFetchCredentialIssuerMetadata(cause: fetchError))
    }
  }
  
  private func determineAcceptHeader(for policy: IssuerMetadataPolicy) -> String {
    switch policy {
    case .requireSigned:
      return "application/jwt"
    case .preferSigned:
      return "application/jwt, application/json"
    case .ignoreSigned:
      return "application/json"
    }
  }
}

