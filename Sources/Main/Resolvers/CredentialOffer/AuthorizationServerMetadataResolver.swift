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
  case appendPathComponents(String, String)
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
    
    // According to the spec https://www.rfc-editor.org/rfc/rfc8414.html#section-3
    //“.well-known/oauth-authorization-server” need to be inserted after removing the path components first. e.g :
    // https://example.com/.well-known/oauth-authorization-server/path1/path2
    // We provide a fallback that simply appends the components
    // Note: this fallback mechanism will be removed at a future date
    do {
      guard let insertedUrl = modifyURL(
        url: url,
        modificationType: .insertPathComponents(".well-known", "openid-configuration")
      ) else {
        return nil
      }
      
      return try await fetcher.fetch(
        url: insertedUrl
      ).get()
      
    } catch {
      
      guard let appendedUrl = modifyURL(
        url: url,
        modificationType: .appendPathComponents(".well-known", "openid-configuration")
      ) else {
        return nil
      }
      
      return try? await fetcher.fetch(
        url: appendedUrl
      ).get()
    }
  }
  
  private func fetchAuthorizationServerMetadata(
    fetcher: Fetcher<AuthorizationServerMetadata>,
    url: URL
  ) async -> AuthorizationServerMetadata? {
    
    //According to the spec https://www.rfc-editor.org/rfc/rfc8414.html#section-3
    //“.well-known/oauth-authorization-server” need to be inserted after removing the path components first. e.g :
    // https://example.com/.well-known/oauth-authorization-server/path1/path2
    // We provide a fallback that simply appends the components
    do {
      guard let insertedUrl = modifyURL(
        url: url,
        modificationType: .appendPathComponents(".well-known", "oauth-authorization-server")
      ) else {
        return nil
      }
      
      return try await fetcher.fetch(
        url: insertedUrl
      ).get()
      
    } catch {
      
      guard let appendedUrl = modifyURL(
        url: url,
        modificationType: .insertPathComponents(".well-known", "oauth-authorization-server")
      ) else {
        return nil
      }
      
      return try? await fetcher.fetch(
        url: appendedUrl
      ).get()
    }
  }
}

extension AuthorizationServerMetadataResolver {
  
  func modifyURL(
    url: URL,
    modificationType: URLModificationType
  ) -> URL? {
    var urlComponents = URLComponents(url: url, resolvingAgainstBaseURL: false)
    
    switch modificationType {
    case .appendPathComponents(let component1, let component2):
      urlComponents?.path.append(contentsOf: "/\(component1)/\(component2)")
      
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
