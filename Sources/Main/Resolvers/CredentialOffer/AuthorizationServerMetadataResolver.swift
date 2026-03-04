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

public enum URLModificationType {
  case insertPathComponents(String, String)
}

protocol AuthorizationServerMetadataResolverType {
  /// Resolves client metadata asynchronously.
  ///
  /// - Parameters:
  ///   - fetcher: The fetcher object responsible for fetching metadata. Default value is Fetcher<ClientMetaData>().
  ///   - source: The input source for resolving metadata.
  /// - Returns: An asynchronous result containing the resolved metadata or an error of type ResolvingError.
  func resolve(
    url: URL
  ) async -> Result<IdentityAndAccessManagementMetadata, Error>
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
  ) async -> Result<IdentityAndAccessManagementMetadata, Error> {
    
    if let oauth = await fetchAuthorizationServerMetadata(
      fetcher: oauthFetcher,
      url: url
    ) {
      return .success(.oauth(oauth))
      
    } else if let oidc = await fetchOIDCProviderMetadata(
      fetcher: oidcFetcher,
      url: url
    ) {
      return .success(.oidc(oidc))
    }
    
    return .failure(ValidationError.error(reason: "Unable to fetch metadata"))
  }
  
  private func fetchOIDCProviderMetadata(
    fetcher: Fetcher<OIDCProviderMetadata>,
    url: URL
  ) async -> OIDCProviderMetadata? {

    // Spec-compliant discovery only: insert ".well-known/openid-configuration"
    let wellKnown = ".well-known"
    let configuration = "openid-configuration"

    guard let insertedUrl = modifyURL(
      url: url,
      modificationType: .insertPathComponents(wellKnown, configuration)
    ) else {
      return nil
    }

    return try? await fetcher.fetch(url: insertedUrl).get()
  }

  private func fetchAuthorizationServerMetadata(
    fetcher: Fetcher<AuthorizationServerMetadata>,
    url: URL
  ) async -> AuthorizationServerMetadata? {

    // Spec-compliant discovery only: insert ".well-known/oauth-authorization-server"
    let wellKnown = ".well-known"
    let server = "oauth-authorization-server"

    guard let insertedUrl = modifyURL(
      url: url,
      modificationType: .insertPathComponents(wellKnown, server)
    ) else {
      return nil
    }

    return try? await fetcher.fetch(url: insertedUrl).get()
  }
}

extension AuthorizationServerMetadataResolver {

  func modifyURL(
    url: URL,
    modificationType: URLModificationType
  ) -> URL? {
    var urlComponents = URLComponents(url: url, resolvingAgainstBaseURL: false)
    
    switch modificationType {
    case .insertPathComponents(let component1, let component2):
      var pathComponents = urlComponents?.path.split(separator: "/").map(String.init) ?? []
      
      if let _ = url.host {
        if pathComponents.isEmpty {
          pathComponents.append(component1)
          pathComponents.append(component2)
          
        } else {
          pathComponents.insert(component2, at: 0)
          pathComponents.insert(component1, at: 0)
        }
        urlComponents?.path = "/" + pathComponents.joined(separator: "/")
      }
    }
    return urlComponents?.url
  }
}
