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

@testable import OpenID4VCI

struct Wallet {
  let actingUser: ActingUser
  let bindingKeys: [BindingKey]
  let session: Networking

  init(
    actingUser: ActingUser,
    bindingKeys: [BindingKey],
    session: Networking = Self.walletSession
  ) {
    self.actingUser = actingUser
    self.bindingKeys = bindingKeys
    self.session = session
  }

  static let walletSession: Networking = {
    /*let delegate = SelfSignedSessionDelegate()
    let configuration = URLSessionConfiguration.default
    return URLSession(
      configuration: configuration,
      delegate: delegate,
      delegateQueue: nil
    )*/
    URLSession.shared
  }()
}

extension Wallet {
  func issueByCredentialIdentifier(
    _ identifier: String,
    config: OpenId4VCIConfig
  ) async throws -> Credential {
    let credentialConfigurationIdentifier = try CredentialConfigurationIdentifier(value: identifier)
    let credentialIssuerIdentifier = try CredentialIssuerId(CREDENTIAL_ISSUER_PUBLIC_URL)
    
    let resolver = CredentialIssuerMetadataResolver(
      fetcher:  MetadataFetcher(rawFetcher: RawDataFetcher(session: self.session)))

    let issuerMetadata = try await resolver.resolve(
      source: .credentialIssuer(
        credentialIssuerIdentifier
      ),
      policy: config.issuerMetadataPolicy
    )
    
    switch issuerMetadata {
    case .success(let metaData):
      if let authorizationServer = metaData.authorizationServers?.first {
          let resolver = AuthorizationServerMetadataResolver(
            oidcFetcher: Fetcher(session: self.session),
            oauthFetcher: Fetcher(session: self.session)
          )
        let authServerMetadata = await resolver.resolve(url: authorizationServer)
        
        let offer = try CredentialOffer(
          credentialIssuerIdentifier: credentialIssuerIdentifier,
          credentialIssuerMetadata: metaData,
          credentialConfigurationIdentifiers: [
            .init(value: identifier)
          ],
          grants: .authorizationCode(
            .init(
              authorizationServer: authorizationServer
            )
          ),
          authorizationServerMetadata: try authServerMetadata.get()
        )
        return try await issueOfferedCredential(
          offer: offer,
          credentialConfigurationIdentifier: credentialConfigurationIdentifier,
          config: config
        )
        
      } else {
        throw ValidationError.error(reason: "Invalid authorization server")
      }
    case .failure(let error):
      throw ValidationError.error(reason: "Invalid issuer metadata: \(error.localizedDescription)")
    }
  }
  
  private func issueMultipleOfferedCredentialWithProof(
    offer: CredentialOffer,
    config: OpenId4VCIConfig
  ) async throws -> [(String, Credential)] {
    
    let issuerMetadata = offer.credentialIssuerMetadata
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: issuerMetadata,
      config: config,
      parPoster: Poster(session: self.session),
      tokenPoster: Poster(session: self.session),
      requesterPoster: Poster(session: self.session),
      deferredRequesterPoster: Poster(session: self.session),
      notificationPoster: Poster(session: self.session),
      dpopConstructor: dpopConstructor(
        algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported
      )
    )
    
    let authorized = try await authorizeRequestWithAuthCodeUseCase(
      issuer: issuer,
      offer: offer
    )
    
    return try await offer.credentialIssuerMetadata.credentialsSupported.filter({ (key: CredentialConfigurationIdentifier, _: CredentialSupported) in
      offer.credentialConfigurationIdentifiers.contains { id in
        key == id
      }
    }).asyncCompactMap { (credentialConfigurationIdentifier, _) in
      guard let scope = issuerMetadata.credentialsSupported[credentialConfigurationIdentifier]?.getScope() else {
        throw ValidationError.error(reason: "Cannot find scope for \(credentialConfigurationIdentifier)")
      }
      
      let data = try await submissionUseCase(
        issuer: issuer,
        authorized: authorized,
        credentialConfigurationIdentifier: credentialConfigurationIdentifier
      )
      return (scope, data)
    }
  }
  
  private func issueOfferedCredential(
    offer: CredentialOffer,
    credentialConfigurationIdentifier: CredentialConfigurationIdentifier,
    config: OpenId4VCIConfig
  ) async throws -> Credential {
    
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: config,
      dpopConstructor: dpopConstructor(
        algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported
      ),
      session: self.session
    )
    
    // Authorize with auth code flow
    let authorized = try await authorizeRequestWithAuthCodeUseCase(
      issuer: issuer,
      offer: offer
    )
    
    return try await submissionUseCase(
      issuer: issuer,
      authorized: authorized,
      credentialConfigurationIdentifier: credentialConfigurationIdentifier
    )
  }
}

extension Wallet {
  
  func issueByCredentialOfferUrlMultipleFormats(
    offerUri: String,
    config: OpenId4VCIConfig
  ) async throws -> [(String, Credential)] {
    let resolver = CredentialOfferRequestResolver(
      fetcher: Fetcher(session: self.session),
      credentialIssuerMetadataResolver: CredentialIssuerMetadataResolver(
        fetcher: MetadataFetcher(rawFetcher: RawDataFetcher(session: self.session))
      ),
      authorizationServerMetadataResolver: AuthorizationServerMetadataResolver(
        oidcFetcher: Fetcher(session: self.session),
        oauthFetcher: Fetcher(session: self.session)
      )
    )
    let result = await resolver
      .resolve(
        source: try .init(
          urlString: offerUri
        ),
        policy: config.issuerMetadataPolicy
      )
    
    switch result {
    case .success(let offer):
      return try await issueMultipleOfferedCredentialWithProof(
        offer: offer,
        config: config
      )
    case .failure(let error):
      throw ValidationError.error(reason: "Unable to resolve credential offer: \(error.localizedDescription)")
    }
  }
  
  func issueByCredentialOfferUrl(
    offerUri: String,
    scope: String,
    config: OpenId4VCIConfig
  ) async throws -> Credential {
      let result = await CredentialOfferRequestResolver(
        fetcher: Fetcher(session: self.session),
        credentialIssuerMetadataResolver: CredentialIssuerMetadataResolver(
          fetcher: MetadataFetcher(rawFetcher: RawDataFetcher(session: self.session))
        ),
        authorizationServerMetadataResolver: AuthorizationServerMetadataResolver(
          oidcFetcher: Fetcher(session: self.session),
          oauthFetcher: Fetcher(session: self.session)
        )
      ).resolve(
        source: try .init(
          urlString: offerUri
        ),
        policy: config.issuerMetadataPolicy
      )
    
    switch result {
    case .success(let offer):
      return try await issueOfferedCredentialWithProof(
        offer: offer,
        scope: scope,
        config: config
      )
    case .failure(let error):
      throw ValidationError.error(reason: "Unable to resolve credential offer: \(error.localizedDescription)")
    }
  }
  
  func issueByCredentialOfferUrl_DPoP(
    offerUri: String,
    scope: String,
    config: OpenId4VCIConfig
  ) async throws -> Credential {
    let result = await CredentialOfferRequestResolver(
      fetcher: Fetcher(session: self.session),
      credentialIssuerMetadataResolver: CredentialIssuerMetadataResolver(
        fetcher: MetadataFetcher(rawFetcher: RawDataFetcher(session: self.session))
      ),
      authorizationServerMetadataResolver: AuthorizationServerMetadataResolver(
        oidcFetcher: Fetcher(session: self.session),
        oauthFetcher: Fetcher(session: self.session)
      )
    ).resolve(
        source: try .init(
          urlString: offerUri
        ),
        policy: config.issuerMetadataPolicy
      )
    
    switch result {
    case .success(let offer):
      return try await issueOfferedCredentialWithProof_DPoP(
        offer: offer,
        scope: scope,
        config: config
      )
    case .failure(let error):
      throw ValidationError.error(reason: "Unable to resolve credential offer: \(error.localizedDescription)")
    }
  }
  
  private func issueOfferedCredentialWithProof(
    offer: CredentialOffer,
    scope: String,
    config: OpenId4VCIConfig
  ) async throws -> Credential {
    
    let issuerMetadata = offer.credentialIssuerMetadata
    guard let credentialConfigurationIdentifier = issuerMetadata.credentialsSupported.keys.first(where: { $0.value == scope }) else {
      throw ValidationError.error(reason: "Cannot find credential identifier for \(scope)")
    }
    
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: config,
      parPoster: Poster(session: self.session),
      tokenPoster: Poster(session: self.session),
      requesterPoster: Poster(session: self.session),
      deferredRequesterPoster: Poster(session: self.session),
      notificationPoster: Poster(session: self.session),
      dpopConstructor: dpopConstructor(
        algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported
      )
    )
    
    let authorized = try await authorizeRequestWithAuthCodeUseCase(
      issuer: issuer,
      offer: offer
    )
    
    return try await submissionUseCase(
      issuer: issuer,
      authorized: authorized,
      credentialConfigurationIdentifier: credentialConfigurationIdentifier
    )
  }
  
  private func issueOfferedCredentialWithProof_DPoP(
    offer: CredentialOffer,
    scope: String,
    config: OpenId4VCIConfig
  ) async throws -> Credential {
    
    let issuerMetadata = offer.credentialIssuerMetadata
    guard let credentialConfigurationIdentifier = issuerMetadata.credentialsSupported.keys.first(where: { $0.value == scope }) else {
      throw ValidationError.error(reason: "Cannot find credential identifier for \(scope)")
    }
    
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: config,
      parPoster: Poster(session: self.session),
      tokenPoster: Poster(session: self.session),
      requesterPoster: Poster(session: self.session),
      deferredRequesterPoster: Poster(session: self.session),
      notificationPoster: Poster(session: self.session),
      dpopConstructor: dpopConstructor(
        algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported
      )
    )
    
    let authorized = try await authorizeRequestWithAuthCodeUseCase(
      issuer: issuer,
      offer: offer
    )
    
    return try await submissionUseCase(
      issuer: issuer,
      authorized: authorized,
      credentialConfigurationIdentifier: credentialConfigurationIdentifier
    )
  }
  
  func authorizeRequestWithAuthCodeUseCase(
    issuer: IssuerType,
    offer: CredentialOffer
  ) async throws -> AuthorizedRequest {
    
    let pushedAuthorizationRequestEndpoint: String? = switch offer.authorizationServerMetadata {
    case .oidc(let metaData):
      metaData.pushedAuthorizationRequestEndpoint
    case .oauth(let metaData):
      metaData.pushedAuthorizationRequestEndpoint
    }
    
    print("--> [AUTHORIZATION] Placing PAR to AS server's endpoint \(pushedAuthorizationRequestEndpoint ?? "N/A")")
    
    let parPlaced = try await issuer.prepareAuthorizationRequest(
      credentialOffer: offer
    )
    
    if case let .success(request) = parPlaced,
       case let .prepared(parRequested) = request {
      print("--> [AUTHORIZATION] Placed PAR. Get authorization code URL is: \(parRequested.authorizationCodeURL)")
      
      var unAuthorized: Result<AuthorizationRequestPrepared, Error>
      var authorizationCode: String
      
      authorizationCode = try await loginUserAndGetAuthCode(
        getAuthorizationCodeUrl: parRequested.authorizationCodeURL.url,
        actingUser: actingUser
      ) ?? { throw  ValidationError.error(reason: "Could not retrieve authorization code") }()
      let issuanceAuthorization: IssuanceAuthorization = .authorizationCode(authorizationCode: authorizationCode)
      unAuthorized = await issuer.handleAuthorizationCode(
        request: request,
        authorizationCode: issuanceAuthorization
      )
      /*
      authorizationCode = ""
      let _: IssuanceAuthorization = .authorizationCode(authorizationCode: authorizationCode)
      unAuthorized = await issuer.handleAuthorizationCode(
        request: request,
        code: &authorizationCode
      )
       */
      print("--> [AUTHORIZATION] Authorization code retrieved: \(authorizationCode)")
      
      switch unAuthorized {
      case .success(let request):
        let authorizedRequest = await issuer.authorizeWithAuthorizationCode(
          request: request,
          authorizationDetailsInTokenRequest: .doNotInclude
        )
        if case let .success(authorized) = authorizedRequest {
          print("--> [AUTHORIZATION] Authorization code exchanged with access token : \(authorized.accessToken)")
          
          _ = authorized.accessToken.isExpired(
            issued: authorized.timeStamp,
            at: Date().timeIntervalSinceReferenceDate
          )
          
          return authorized
        }
        
      case .failure(let error):
        throw  ValidationError.error(reason: error.localizedDescription)
      }
    }
    
    throw  ValidationError.error(reason: "Failed to get push authorization code request")
  }
  
  private func submissionUseCase(
    issuer: Issuer,
    authorized: AuthorizedRequest,
    credentialConfigurationIdentifier: CredentialConfigurationIdentifier?
  ) async throws -> Credential {
    
    guard let credentialConfigurationIdentifier else {
      throw ValidationError.error(reason: "Credential configuration identifier not found")
    }
    
    let payload: IssuanceRequestPayload = .configurationBased(
      credentialConfigurationIdentifier: credentialConfigurationIdentifier
    )
    
    let encryptionSpec = testEncryptionSpec()
    let requestOutcome = try await issuer.requestCredential(
      request: authorized,
      bindingKeys: bindingKeys,
      requestPayload: payload,
      encryptionSpec: encryptionSpec
    ) {
      Issuer.createResponseEncryptionSpec($0)
    }
    
    switch requestOutcome {
    case .success(let request):
      switch request {
      case .success(let response):
        if let result = response.credentialResponses.first {
          switch result {
          case .deferred(let transactionId, let interval):
            
            print("--> [DEFERRED] Retry after: \(interval)")
            
            return try await deferredCredentialUseCase(
              issuer: issuer,
              authorized: authorized,
              transactionId: transactionId
            )
          case .issued(_, let credential, _, _):
            return credential
          }
        } else {
          throw ValidationError.error(reason: "No credential response results available")
        }
      case .invalidProof:
        throw ValidationError.error(reason: "Although providing a proof with c_nonce the proof is still invalid")
      case .failed(let error):
        throw ValidationError.error(reason: error.localizedDescription)
      }
    case .failure(let error): throw ValidationError.error(reason: error.localizedDescription)
    }
  }
  
  private func deferredCredentialUseCase(
    issuer: Issuer,
    authorized: AuthorizedRequest,
    transactionId: TransactionId
  ) async throws -> Credential {
    print("--> [ISSUANCE] Got a deferred issuance response from server with transaction_id \(transactionId.value). Retrying issuance...")
    
    let deferredRequestResponse = try await issuer.requestDeferredCredential(
      request: authorized,
      transactionId: transactionId,
      dPopNonce: nil
    )
    
    switch deferredRequestResponse {
    case .success(let response):
      switch response {
      case .issued(let credential):
        return credential
      case .issuancePending(_, let interval):
        throw ValidationError.error(reason: "Credential not ready yet. Try after \(interval)")
      case .errored(_, let errorDescription):
        throw ValidationError.error(reason: "\(errorDescription ?? "Something went wrong with your deferred request response")")
      case .issuanceStillPending(let interval):
        throw ValidationError.error(reason: "Credential not ready yet. Try after \(interval)")
      }
    case .failure(let error):
      throw ValidationError.error(reason: error.localizedDescription)
    }
  }
}

extension Wallet {
  private func loginUserAndGetAuthCode(
    getAuthorizationCodeUrl: URL,
    actingUser: ActingUser
  ) async throws -> String? {
    let helper = WebpageHelper()
    return try await helper.submit(
      formUrl: getAuthorizationCodeUrl,
      username: actingUser.username,
      password: actingUser.password
    )
  }
}
