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

public actor CredentialOfferRequestResolver: ResolverType {
  /// Resolves client metadata asynchronously.
  ///
  /// - Parameters:
  ///   - fetcher: The fetcher object responsible for fetching metadata. Default value is Fetcher<ClientMetaData>().
  ///   - source: The input source for resolving metadata.
  /// - Returns: An asynchronous result containing the resolved metadata or an error of type ResolvingError.
  public func resolve(
    fetcher: Fetcher<CredentialOfferRequestObject> = Fetcher(),
    source: CredentialOfferSource?
  ) async -> Result<CredentialOfferRequestObject?, CredentialError> {
    guard let source = source else { return .success(nil) }
    switch source {
    case .passByValue(let value):
      guard let offer: CredentialOfferRequestObject = .init(jsonString: value) else {
        return .failure(.genericError)
      }
      return .success(offer)
    case .fetchByReference(let url):
      let result = await fetcher.fetch(url: url)
      let metaData = try? result.get()
      if let metaData = metaData {
        return .success(metaData)
      }
      return .failure(.genericError)
    }
  }
}
