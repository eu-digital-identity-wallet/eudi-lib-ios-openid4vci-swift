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

protocol AuthorizationServerMetadataResolverType {
  /// Resolves client metadata asynchronously.
  ///
  /// - Parameters:
  ///   - fetcher: The fetcher object responsible for fetching metadata. Default value is Fetcher<ClientMetaData>().
  ///   - source: The input source for resolving metadata.
  /// - Returns: An asynchronous result containing the resolved metadata or an error of type ResolvingError.
  func resolve(
    url: URL
  ) async -> Result<CIAuthorizationServerMetadata, Error>
}

public actor AuthorizationServerMetadataResolver: AuthorizationServerMetadataResolverType {
  
  private let oidcFetcher: Fetcher<OIDCProviderMetadata>
  private let oauthFetcher: Fetcher<AuthorizationServerMetadata>
  
  public init(
    oidcFetcher: Fetcher<OIDCProviderMetadata> = Fetcher(),
    oauthFetcher: Fetcher<AuthorizationServerMetadata> = Fetcher()
  ) {
    self.oidcFetcher = oidcFetcher
    self.oauthFetcher = oauthFetcher
  }
  
  /// Resolves client metadata asynchronously.
  ///
  /// - Parameters:
  ///   - fetcher: The fetcher object responsible for fetching metadata. Default value is Fetcher<ClientMetaData>().
  ///   - source: The input source for resolving metadata.
  /// - Returns: An asynchronous result containing the resolved metadata or an error of type ResolvingError.
  public func resolve(
    url: URL
  ) async -> Result<CIAuthorizationServerMetadata, Error> {
    
    if let oidc = await fetchOIDCProviderMetadata(
      fetcher: oidcFetcher,
      url: url
    ) {
      return .success(.oidc(oidc))
      
    } else if let oauth = await fetchAuthorizationServerMetadata(
      fetcher: oauthFetcher,
      url: url
    ) {
      return .success(.oauth(oauth))
    }
    
    return .failure(ValidationError.error(reason: "Unable to fetch metadata"))
  }
  
  private func fetchOIDCProviderMetadata(
    fetcher: Fetcher<OIDCProviderMetadata>,
    url: URL
  ) async -> OIDCProviderMetadata? {
    try? await fetcher.fetch(
      url: url
        .appendingPathComponent(".well-known")
        .appendingPathComponent("openid-configuration")
    ).get()
  }
  
  private func fetchAuthorizationServerMetadata(
    fetcher: Fetcher<AuthorizationServerMetadata>,
    url: URL
  ) async -> AuthorizationServerMetadata? {
    try? await fetcher.fetch(
      url: url
        .appendingPathComponent(".well-known")
        .appendingPathComponent("oauth-authorization-server")
    ).get()
  }
}
