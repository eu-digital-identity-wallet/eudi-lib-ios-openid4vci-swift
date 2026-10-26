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
import SwiftyJSON

public protocol CredentialOfferRequestResolverType {
  /// The input type for resolving a type.
  associatedtype InputType

  /// The output type for resolved type. Must be Codable and Equatable.
  associatedtype OutputType: Codable, Equatable
  
  /// The fetch type for resolved type. Must be Codable and Equatable.
  associatedtype FetchType: Codable, Equatable

  /// The error type for resolving type. Must conform to the Error protocol.
  associatedtype ErrorType: Error

  /// Resolves type asynchronously.
  ///
  /// - Parameters:
  ///   - fetcher: The fetcher object responsible for fetching data.
  ///   - source: The input source for resolving data.
  /// - Returns: An asynchronous result containing the resolved data or an error.
  func resolve(
    fetcher: Fetcher<FetchType>,
    source: InputType?
  ) async -> Result<OutputType?, ErrorType>
}

public actor CredentialOfferRequestResolver {
  
  private let fetcher: Fetcher<CredentialOfferRequestObject>
  private let credentialIssuerMetadataResolver: CredentialIssuerMetadataResolver
  private let authorizationServerMetadataResolver: AuthorizationServerMetadataResolver
  
  /// Initializes an instance of YourClass.
  ///
  /// - Parameters:
  ///   - credentialIssuerMetadataResolver: An object responsible for resolving credential issuer metadata.
  ///   - authorizationServerMetadataResolver: An object responsible for resolving authorization server metadata.
  public init(
    fetcher: Fetcher<CredentialOfferRequestObject> = Fetcher(),
    credentialIssuerMetadataResolver: CredentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(),
    authorizationServerMetadataResolver: AuthorizationServerMetadataResolver = AuthorizationServerMetadataResolver()
  ) {
    self.fetcher = fetcher
    self.credentialIssuerMetadataResolver = credentialIssuerMetadataResolver
    self.authorizationServerMetadataResolver = authorizationServerMetadataResolver
  }
  
  /// Resolves client metadata asynchronously.
  ///
  /// - Parameters:
  ///   - fetcher: The fetcher object responsible for fetching metadata. Default value is Fetcher<ClientMetaData>().
  ///   - source: The input source for resolving metadata.
  /// - Returns: An asynchronous result containing the resolved metadata or an error of type ResolvingError.
  public func resolve(
    source: CredentialOfferRequest?,
    policy: IssuerMetadataPolicy
  ) async -> Result<CredentialOffer, Error> {
    guard let source = source else { return .failure(ValidationError.error(reason: "Invalid source")) }
    do {
      let credentialOfferRequestObject: CredentialOfferRequestObject
      switch source {
      case .passByValue(let value):
        guard let parsed = CredentialOfferRequestObject(jsonString: value) else {
          return .failure(ValidationError.error(reason: "Unable to parse credential offer request"))
        }
        credentialOfferRequestObject = parsed

      case .fetchByReference(let url):
        switch await fetcher.fetch(url: url) {
        case .success(let fetched):
          credentialOfferRequestObject = fetched
        case .failure(let error) where error.isNetworkFailure:
          return .failure(ValidationError.networkError(.init(stage: .GET, url: url, fetchError: error)))
        case .failure:
          return .failure(ValidationError.error(reason: "Unable to fetch credential offer request by reference"))
        }
      }

      let credentialIssuerId = try CredentialIssuerId(credentialOfferRequestObject.credentialIssuer)
      let credentialIssuerMetadata = try await resolveCredentialIssuerMetadata(
        issuerId: credentialIssuerId,
        policy: policy
      )

      let authServerHint = getAuthorizationServerFromGrants(credentialOfferRequestObject.grants)
      let authorizationServerResult = selectAuthorizationServer(
        hint: authServerHint,
        availableServers: credentialIssuerMetadata.authorizationServers
      )

      guard case .success(let authorizationServer) = authorizationServerResult else {
        if case .failure(let error) = authorizationServerResult {
          return .failure(error)
        }
        return .failure(ValidationError.error(reason: "Invalid authorization metadata"))
      }

      let authorizationServerMetadata = try await resolveAuthorizationServerMetadata(url: authorizationServer)

      let domain = try toDomain(
        credentialOfferRequestObject: credentialOfferRequestObject,
        credentialIssuerId: credentialIssuerId,
        credentialIssuerMetadata: credentialIssuerMetadata,
        authorizationServerMetadata: authorizationServerMetadata
      )
      return .success(domain)

    } catch let error as ValidationError {
      return .failure(error)
    } catch let error as CredentialIssuerMetadataError {
      return .failure(error)
    } catch {
      return .failure(ValidationError.error(reason: error.localizedDescription))
    }
  }

  /// Resolves the credential issuer metadata. A network failure while fetching it is reported as such,
  /// any other metadata error (not signed, not trusted, not parseable) is passed on unchanged.
  private func resolveCredentialIssuerMetadata(
    issuerId: CredentialIssuerId,
    policy: IssuerMetadataPolicy
  ) async throws -> CredentialIssuerMetadata {
    let result = try await credentialIssuerMetadataResolver.resolve(
      source: .credentialIssuer(issuerId),
      policy: policy
    )
    switch result {
    case .success(let metadata):
      return metadata
    case .failure(.unableToFetchCredentialIssuerMetadata(let cause)):
      guard let fetchError = cause as? FetchError, fetchError.isNetworkFailure else {
        throw ValidationError.error(reason: "Invalid credential metadata")
      }
      throw ValidationError.networkError(.init(stage: .GET, url: issuerId.url, fetchError: fetchError))
    case .failure(let error):
      throw error
    }
  }

  /// Resolves the authorization server metadata, keeping a network failure as the reason.
  private func resolveAuthorizationServerMetadata(url: URL) async throws -> IdentityAndAccessManagementMetadata {
    switch await authorizationServerMetadataResolver.resolve(url: url) {
    case .success(let metadata):
      return metadata
    case .failure(let error):
      if case ValidationError.networkError = error {
        throw error
      }
      throw ValidationError.error(reason: "Invalid authorization metadata")
    }
  }
  
  /// Extracts the authorization server URL from the grants if specified in the credential offer.
  /// Checks both authorization code and pre-authorization code grants as per the specification.
  private func getAuthorizationServerFromGrants(_ grants: GrantsDTO?) -> URL? {
    guard let grants = grants else { return nil }

    // Check authorization code grant first
    if let authServer = grants.authorizationCode?.authorizationServer,
       !authServer.isEmpty,
       let url = URL(string: authServer) {
      return url
    }

    // Check pre-authorization code grant
    if let authServer = grants.preAuthorizationCode?.authorizationServer,
       !authServer.isEmpty,
       let url = URL(string: authServer) {
      return url
    }

    return nil
  }

  /// Selects the authorization server based on the hint from the credential offer.
  /// If a hint is provided, validates it against the available servers.
  /// If no hint is provided, falls back to the first available server.
  private func selectAuthorizationServer(
    hint: URL?,
    availableServers: [URL]?
  ) -> Result<URL, Error> {
    guard let availableServers = availableServers, !availableServers.isEmpty else {
      return .failure(ValidationError.error(reason: "No authorization servers available"))
    }

    if let hint = hint {
      if availableServers.contains(hint) {
        return .success(hint)
      } else {
        return .failure(ValidationError.error(
          reason: "Authorization server '\(hint.absoluteString)' from credential offer is not in the list of available authorization servers"
        ))
      }
    }

    if let first = availableServers.first {
      return .success(first)
    }
    return .failure(ValidationError.error(
      reason: "No available authorization servers"
    ))
  }

  func toDomain(
    credentialOfferRequestObject: CredentialOfferRequestObject,
    credentialIssuerId: CredentialIssuerId,
    credentialIssuerMetadata: CredentialIssuerMetadata?,
    authorizationServerMetadata: IdentityAndAccessManagementMetadata
  ) throws -> CredentialOffer {
    
    guard let credentialIssuerMetadata = credentialIssuerMetadata else {
      throw ValidationError.error(reason: "Invalid to fetch credential offer request by reference")
    }
    
    do {
      let credentialConfigurationIdentifiers: [CredentialConfigurationIdentifier] = credentialOfferRequestObject.credentialConfigurationIds.compactMap { try? CredentialConfigurationIdentifier(value: $0.stringValue) }
      let grants = try credentialOfferRequestObject.grants?.toDomain()
      return try .init(
        credentialIssuerIdentifier: credentialIssuerId,
        credentialIssuerMetadata: credentialIssuerMetadata,
        credentialConfigurationIdentifiers: credentialConfigurationIdentifiers,
        grants: grants,
        authorizationServerMetadata: authorizationServerMetadata
      )
    } catch {
      throw ValidationError.error(reason: error.localizedDescription)
    }
  }
}
