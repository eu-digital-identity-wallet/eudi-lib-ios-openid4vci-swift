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

// Only RFC 8414 / OIDC-compliant discovery is supported.
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

  private enum DiscoveryFailure: Error {
    case notUsable
    case network(NetworkFailure)

    var networkFailure: NetworkFailure? {
      if case .network(let failure) = self {
        return failure
      }
      return nil
    }
  }

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

    var networkFailure: NetworkFailure?

    switch await fetchAuthorizationServerMetadata(fetcher: oauthFetcher, url: url) {
    case .success(let oauth):
      return .success(.oauth(oauth))
    case .failure(let failure):
      networkFailure = failure.networkFailure
    }

    switch await fetchOIDCProviderMetadata(fetcher: oidcFetcher, url: url) {
    case .success(let oidc):
      return .success(.oidc(oidc))
    case .failure(let failure):
      networkFailure = failure.networkFailure ?? networkFailure
    }

    if let networkFailure {
      return .failure(ValidationError.networkError(networkFailure))
    }
    return .failure(ValidationError.error(reason: "Unable to fetch metadata"))
  }

  private func fetchOIDCProviderMetadata(
    fetcher: Fetcher<OIDCProviderMetadata>,
    url: URL
  ) async -> Result<OIDCProviderMetadata, DiscoveryFailure> {

    // Spec-compliant discovery only: insert ".well-known/openid-configuration"
    let wellKnown = ".well-known"
    let configuration = "openid-configuration"

    guard let insertedUrl = modifyURL(
      url: url,
      modificationType: .insertPathComponents(wellKnown, configuration)
    ) else {
      return .failure(.notUsable)
    }

    return await fetchDiscoveryDocument(fetcher: fetcher, url: insertedUrl, discoveryURL: url) { $0.issuer }
  }

  private func fetchAuthorizationServerMetadata(
    fetcher: Fetcher<AuthorizationServerMetadata>,
    url: URL
  ) async -> Result<AuthorizationServerMetadata, DiscoveryFailure> {

    // Spec-compliant discovery only: insert ".well-known/oauth-authorization-server"
    let wellKnown = ".well-known"
    let server = "oauth-authorization-server"

    guard let insertedUrl = modifyURL(
      url: url,
      modificationType: .insertPathComponents(wellKnown, server)
    ) else {
      return .failure(.notUsable)
    }

    return await fetchDiscoveryDocument(fetcher: fetcher, url: insertedUrl, discoveryURL: url) { $0.issuer }
  }

  private func fetchDiscoveryDocument<Metadata: Decodable & Sendable>(
    fetcher: Fetcher<Metadata>,
    url: URL,
    discoveryURL: URL,
    issuer: (Metadata) -> String?
  ) async -> Result<Metadata, DiscoveryFailure> {
    switch await fetcher.fetch(url: url) {
    case .success(let metadata):
      guard isIssuerBoundToDiscoveryURL(issuer(metadata), discoveryURL: discoveryURL) else {
        return .failure(.notUsable)
      }
      return .success(metadata)
    case .failure(let error):
      guard let failure = Self.networkFailure(url: url, fetchError: error) else {
        return .failure(.notUsable)
      }
      return .failure(.network(failure))
    }
  }

  private static func networkFailure(url: URL, fetchError: FetchError) -> NetworkFailure? {
    switch fetchError {
    case .networkError:
      return NetworkFailure(stage: .GET, url: url, fetchError: fetchError)
    case .invalidStatusCode(_, let code, _) where code != HTTPStatusCode.notFound: // 404 is not an error in this case
      return NetworkFailure(stage: .GET, url: url, fetchError: fetchError)
    default:
      return nil
    }
  }

  private func isIssuerBoundToDiscoveryURL(_ metadataIssuer: String?, discoveryURL: URL) -> Bool {
    guard let metadataIssuer, !metadataIssuer.isEmpty else { return false }
    return metadataIssuer == discoveryURL.absoluteString
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
