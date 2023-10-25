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

public enum AuthorizationServerMetadataSink {
  case oidc(OIDCProviderMetadata)
  case oauth(AuthorizationServerMetadata)
}

public actor AuthorizationServerMetadataResolver {
  /// Resolves client metadata asynchronously.
  ///
  /// - Parameters:
  ///   - fetcher: The fetcher object responsible for fetching metadata. Default value is Fetcher<ClientMetaData>().
  ///   - source: The input source for resolving metadata.
  /// - Returns: An asynchronous result containing the resolved metadata or an error of type ResolvingError.
  public func resolve(
    oidcFetcher: Fetcher<OIDCProviderMetadata> = Fetcher(),
    oauthFetcher: Fetcher<AuthorizationServerMetadata> = Fetcher(),
    url: URL
  ) async -> Result<AuthorizationServerMetadataSink, CredentialError> {
    
    if let oidc = try? await oidcFetcher.fetch(url: url).get() {
      return .success(.oidc(oidc))
    } else if let oauth = try? await oauthFetcher.fetch(url: url).get() {
      return .success(.oauth(oauth))
    }
    
    return .failure(.genericError)
  }
  
  private func fetchOIDCProviderMetadata(
    fetcher: Fetcher<OIDCProviderMetadata>
  ) async -> OIDCProviderMetadata? {
    nil
  }
  
  private func fetchAuthorizationServerMetadata(
    fetcher: Fetcher<AuthorizationServerMetadata>
  ) async -> AuthorizationServerMetadata? {
    nil
  }
}
