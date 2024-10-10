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
  let bindingKey: BindingKey
  let dPoPConstructor: DPoPConstructorType?
  let session: Networking

  init(
    actingUser: ActingUser,
    bindingKey: BindingKey,
    dPoPConstructor: DPoPConstructorType?,
    session: Networking = Self.walletSession
  ) {
    self.actingUser = actingUser
    self.bindingKey = bindingKey
    self.dPoPConstructor = dPoPConstructor
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
    claimSet: ClaimSet? = nil
  ) async throws -> String {
    let credentialConfigurationIdentifier = try CredentialConfigurationIdentifier(value: identifier)
    let credentialIssuerIdentifier = try CredentialIssuerId(CREDENTIAL_ISSUER_PUBLIC_URL)
    
    let resolver = CredentialIssuerMetadataResolver(
      fetcher: Fetcher(session: self.session)
    )
    let issuerMetadata = await resolver.resolve(
      source: .credentialIssuer(
        credentialIssuerIdentifier
      )
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
          grants: nil,
          authorizationServerMetadata: try authServerMetadata.get()
        )
        return try await issueOfferedCredentialNoProof(
          offer: offer,
          credentialConfigurationIdentifier: credentialConfigurationIdentifier,
          claimSet: claimSet
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
    claimSet: ClaimSet? = nil
  ) async throws -> [(String, String)] {
    
    let issuerMetadata = offer.credentialIssuerMetadata
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: issuerMetadata,
      config: config,
      parPoster: Poster(session: self.session),
      tokenPoster: Poster(session: self.session),
      requesterPoster: Poster(session: self.session),
      deferredRequesterPoster: Poster(session: self.session),
      notificationPoster: Poster(session: self.session)
    )
    
    let authorized = try await authorizeRequestWithAuthCodeUseCase(
      issuer: issuer,
      offer: offer
    )
    
    switch authorized {
    case .noProofRequired:
      return try await offer
        .credentialIssuerMetadata
        .credentialsSupported
        .filter { offer.credentialConfigurationIdentifiers.contains($0.key) }
        .asyncCompactMap { (credentialConfigurationIdentifier, supportedCredential) in
        guard let scope = issuerMetadata.credentialsSupported[credentialConfigurationIdentifier]?.getScope() else {
          throw ValidationError.error(reason: "Cannot find scope for \(credentialConfigurationIdentifier)")
        }

        if let data = try? await noProofRequiredSubmissionUseCase(
          issuer: issuer,
          noProofRequiredState: authorized,
          credentialConfigurationIdentifier: credentialConfigurationIdentifier, 
          claimSet: claimSet
        ) {
          return (scope, data)
        } else {
          return nil
        }
      }
      
    case .proofRequired:
      return try await offer.credentialIssuerMetadata.credentialsSupported.asyncCompactMap { (credentialConfigurationIdentifier, supportedCredential) in
        guard let scope = issuerMetadata.credentialsSupported[credentialConfigurationIdentifier]?.getScope() else {
          throw ValidationError.error(reason: "Cannot find scope for \(credentialConfigurationIdentifier)")
        }
        let data = try await proofRequiredSubmissionUseCase(
          issuer: issuer,
          authorized: authorized,
          credentialConfigurationIdentifier: credentialConfigurationIdentifier,
          claimSet: claimSet
        )
        return (scope, data)
      }
    }
  }
  
  private func issueOfferedCredentialNoProof(
    offer: CredentialOffer,
    credentialConfigurationIdentifier: CredentialConfigurationIdentifier,
    claimSet: ClaimSet? = nil
  ) async throws -> String {
    
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: config,
      parPoster: Poster(session: self.session),
      tokenPoster: Poster(session: self.session),
      requesterPoster: Poster(session: self.session),
      deferredRequesterPoster: Poster(session: self.session),
      notificationPoster: Poster(session: self.session)
    )
    
    // Authorize with auth code flow
    let authorized = try await authorizeRequestWithAuthCodeUseCase(
      issuer: issuer,
      offer: offer
    )
    
    switch authorized {
    case .noProofRequired:
      return try await noProofRequiredSubmissionUseCase(
        issuer: issuer,
        noProofRequiredState: authorized,
        credentialConfigurationIdentifier: credentialConfigurationIdentifier,
        claimSet: claimSet
      )
    case .proofRequired:
      return try await proofRequiredSubmissionUseCase(
        issuer: issuer,
        authorized: authorized,
        credentialConfigurationIdentifier: credentialConfigurationIdentifier,
        claimSet: claimSet
      )
    }
  }
}

extension Wallet {
  
  func issueByCredentialOfferUrlMultipleFormats(
    offerUri: String,
    claimSet: ClaimSet? = nil
  ) async throws -> [(String, String)] {
    let resolver = CredentialOfferRequestResolver(
      fetcher: Fetcher(session: self.session),
      credentialIssuerMetadataResolver: CredentialIssuerMetadataResolver(
        fetcher: Fetcher(session: self.session)
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
        )
      )
    
    switch result {
    case .success(let offer):
      return try await issueMultipleOfferedCredentialWithProof(
        offer: offer,
        claimSet: claimSet
      )
    case .failure(let error):
      throw ValidationError.error(reason: "Unable to resolve credential offer: \(error.localizedDescription)")
    }
  }
  
  func issueByCredentialOfferUrl(
    offerUri: String,
    scope: String,
    claimSet: ClaimSet? = nil
  ) async throws -> String {
      let result = await CredentialOfferRequestResolver(
        fetcher: Fetcher(session: self.session),
        credentialIssuerMetadataResolver: CredentialIssuerMetadataResolver(
          fetcher: Fetcher(session: self.session)
        ),
        authorizationServerMetadataResolver: AuthorizationServerMetadataResolver(
          oidcFetcher: Fetcher(session: self.session),
          oauthFetcher: Fetcher(session: self.session)
        )
      ).resolve(
        source: try .init(
          urlString: offerUri
        )
      )
    
    switch result {
    case .success(let offer):
      return try await issueOfferedCredentialWithProof(
        offer: offer,
        scope: scope,
        claimSet: claimSet
      )
    case .failure(let error):
      throw ValidationError.error(reason: "Unable to resolve credential offer: \(error.localizedDescription)")
    }
  }
  
  func issueByCredentialOfferUrl_DPoP(
    offerUri: String,
    scope: String,
    claimSet: ClaimSet? = nil
  ) async throws -> String {
    let result = await CredentialOfferRequestResolver(
      fetcher: Fetcher(session: self.session),
      credentialIssuerMetadataResolver: CredentialIssuerMetadataResolver(
        fetcher: Fetcher(session: self.session)
      ),
      authorizationServerMetadataResolver: AuthorizationServerMetadataResolver(
        oidcFetcher: Fetcher(session: self.session),
        oauthFetcher: Fetcher(session: self.session)
      )
    ).resolve(
        source: try .init(
          urlString: offerUri
        )
      )
    
    switch result {
    case .success(let offer):
      return try await issueOfferedCredentialWithProof_DPoP(
        offer: offer,
        scope: scope,
        claimSet: claimSet
      )
    case .failure(let error):
      throw ValidationError.error(reason: "Unable to resolve credential offer: \(error.localizedDescription)")
    }
  }
  
  private func issueOfferedCredentialWithProof(
    offer: CredentialOffer,
    scope: String,
    claimSet: ClaimSet? = nil
  ) async throws -> String {
    
    let issuerMetadata = offer.credentialIssuerMetadata
    guard let credentialConfigurationIdentifier = issuerMetadata.credentialsSupported.keys.first(where: { $0.value == scope }) else {
      throw ValidationError.error(reason:  "Cannot find credential identifier for \(scope)")
    }
    
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: config,
      parPoster: Poster(session: self.session),
      tokenPoster: Poster(session: self.session),
      requesterPoster: Poster(session: self.session),
      deferredRequesterPoster: Poster(session: self.session),
      notificationPoster: Poster(session: self.session)
    )
    
    let authorized = try await authorizeRequestWithAuthCodeUseCase(
      issuer: issuer,
      offer: offer
    )
    
    switch authorized {
    case .noProofRequired:
      return try await noProofRequiredSubmissionUseCase(
        issuer: issuer,
        noProofRequiredState: authorized,
        credentialConfigurationIdentifier: credentialConfigurationIdentifier,
        claimSet: claimSet
      )
    case .proofRequired:
      return try await proofRequiredSubmissionUseCase(
        issuer: issuer,
        authorized: authorized,
        credentialConfigurationIdentifier: credentialConfigurationIdentifier,
        claimSet: claimSet
      )
    }
  }
  
  private func issueOfferedCredentialWithProof_DPoP(
    offer: CredentialOffer,
    scope: String,
    claimSet: ClaimSet? = nil
  ) async throws -> String {
    
    let issuerMetadata = offer.credentialIssuerMetadata
    guard let credentialConfigurationIdentifier = issuerMetadata.credentialsSupported.keys.first(where: { $0.value == scope }) else {
      throw ValidationError.error(reason:  "Cannot find credential identifier for \(scope)")
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
      dpopConstructor: dPoPConstructor
    )
    
    let authorized = try await authorizeRequestWithAuthCodeUseCase(
      issuer: issuer,
      offer: offer
    )
    
    switch authorized {
    case .noProofRequired:
      return try await noProofRequiredSubmissionUseCase(
        issuer: issuer,
        noProofRequiredState: authorized,
        credentialConfigurationIdentifier: credentialConfigurationIdentifier,
        claimSet: claimSet
      )
    case .proofRequired:
      return try await proofRequiredSubmissionUseCase(
        issuer: issuer,
        authorized: authorized,
        credentialConfigurationIdentifier: credentialConfigurationIdentifier,
        claimSet: claimSet
      )
    }
  }
  
  func authorizeRequestWithAuthCodeUseCase(
    issuer: Issuer,
    offer: CredentialOffer
  ) async throws -> AuthorizedRequest {
    
    var pushedAuthorizationRequestEndpoint: String? = nil
    if case let .oidc(metaData) = offer.authorizationServerMetadata {
      if let endpoint = metaData.pushedAuthorizationRequestEndpoint {
        pushedAuthorizationRequestEndpoint = endpoint
      }
      
    } else if case let .oauth(metaData) = offer.authorizationServerMetadata {
      if let endpoint = metaData.pushedAuthorizationRequestEndpoint {
        pushedAuthorizationRequestEndpoint = endpoint
      }
    }
    
    print("--> [AUTHORIZATION] Placing PAR to AS server's endpoint \(pushedAuthorizationRequestEndpoint ?? "N/A")")
    
    let parPlaced = try await issuer.pushAuthorizationCodeRequest(
      credentialOffer: offer
    )
    
    if case let .success(request) = parPlaced,
       case let .par(parRequested) = request {
      print("--> [AUTHORIZATION] Placed PAR. Get authorization code URL is: \(parRequested.getAuthorizationCodeURL)")
      
      var unAuthorized: Result<UnauthorizedRequest, Error>
      var authorizationCode: String
      
      authorizationCode = try await loginUserAndGetAuthCode(
        getAuthorizationCodeUrl: parRequested.getAuthorizationCodeURL.url,
        actingUser: actingUser
      ) ?? { throw  ValidationError.error(reason: "Could not retrieve authorization code") }()
      let issuanceAuthorization: IssuanceAuthorization = .authorizationCode(authorizationCode: authorizationCode)
      unAuthorized = await issuer.handleAuthorizationCode(
        parRequested: request,
        authorizationCode: issuanceAuthorization
      )
      /*
      authorizationCode = ""
      let _: IssuanceAuthorization = .authorizationCode(authorizationCode: authorizationCode)
      unAuthorized = await issuer.handleAuthorizationCode(
        parRequested: request,
        code: &authorizationCode
      )
       */
      print("--> [AUTHORIZATION] Authorization code retrieved: \(authorizationCode)")
      
      switch unAuthorized {
      case .success(let request):
        let authorizedRequest = await issuer.requestAccessToken(authorizationCode: request)
        if case let .success(authorized) = authorizedRequest,
           case let .noProofRequired(token, _, _, _) = authorized {
          print("--> [AUTHORIZATION] Authorization code exchanged with access token : \(token.accessToken)")
          
          if let timeStamp = authorized.timeStamp {
            _ = authorized.accessToken?.isExpired(
              issued: timeStamp,
              at: Date().timeIntervalSinceReferenceDate)
          }
          return authorized
        }
        
      case .failure(let error):
        throw  ValidationError.error(reason: error.localizedDescription)
      }
    }
    
    throw  ValidationError.error(reason: "Failed to get push authorization code request")
  }
  
  private func noProofRequiredSubmissionUseCase(
    issuer: Issuer,
    noProofRequiredState: AuthorizedRequest,
    credentialConfigurationIdentifier: CredentialConfigurationIdentifier,
    claimSet: ClaimSet? = nil
  ) async throws -> String {
    switch noProofRequiredState {
    case .noProofRequired:
      let payload: IssuanceRequestPayload = .configurationBased(
        credentialConfigurationIdentifier: credentialConfigurationIdentifier,
        claimSet: claimSet
      )
      let responseEncryptionSpecProvider = { Issuer.createResponseEncryptionSpec($0) }
      let requestOutcome = try await issuer.requestSingle(
        noProofRequest: noProofRequiredState,
        requestPayload: payload,
        responseEncryptionSpecProvider: responseEncryptionSpecProvider
      )
      switch requestOutcome {
      case .success(let request):
        switch request {
        case .success(let response):
          if let result = response.credentialResponses.first {
            switch result {
            case .deferred(let transactionId):
              return try await deferredCredentialUseCase(
                issuer: issuer,
                authorized: noProofRequiredState,
                transactionId: transactionId
              )
            case .issued(let credential, _):
              return credential
            }
          } else {
            throw ValidationError.error(reason: "No credential response results available")
          }
        case .invalidProof(let cNonce, _):
          return try await proofRequiredSubmissionUseCase(
            issuer: issuer,
            authorized: noProofRequiredState.handleInvalidProof(cNonce: cNonce),
            credentialConfigurationIdentifier: credentialConfigurationIdentifier,
            claimSet: claimSet
          )
        case .failed(error: let error):
          throw ValidationError.error(reason: error.localizedDescription)
        }
        
      case .failure(let error):
        throw ValidationError.error(reason: error.localizedDescription)
      }
    default: throw ValidationError.error(reason: "Illegal noProofRequiredState case")
    }
  }
  
  private func proofRequiredSubmissionUseCase(
    issuer: Issuer,
    authorized: AuthorizedRequest,
    credentialConfigurationIdentifier: CredentialConfigurationIdentifier?,
    claimSet: ClaimSet? = nil
  ) async throws -> String {
    
    guard let credentialConfigurationIdentifier else {
      throw ValidationError.error(reason: "Credential configuration identifier not found")
    }
    
    let payload: IssuanceRequestPayload = .configurationBased(
      credentialConfigurationIdentifier: credentialConfigurationIdentifier,
      claimSet: claimSet
    )
    
    let responseEncryptionSpecProvider = { Issuer.createResponseEncryptionSpec($0) }
    let requestOutcome = try await issuer.requestSingle(
      proofRequest: authorized,
      bindingKey: bindingKey,
      requestPayload: payload,
      responseEncryptionSpecProvider: responseEncryptionSpecProvider
    )
    
    switch requestOutcome {
    case .success(let request):
      switch request {
      case .success(let response):
        if let result = response.credentialResponses.first {
          switch result {
          case .deferred(let transactionId):
            return try await deferredCredentialUseCase(
              issuer: issuer,
              authorized: authorized,
              transactionId: transactionId
            )
          case .issued(let credential, _):
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
  ) async throws -> String {
    print("--> [ISSUANCE] Got a deferred issuance response from server with transaction_id \(transactionId.value). Retrying issuance...")
    
    let deferredRequestResponse = try await issuer.requestDeferredIssuance(
      proofRequest: authorized,
      transactionId: transactionId
    )
    
    switch deferredRequestResponse {
    case .success(let response):
      switch response {
      case .issued(let credential):
        return credential
      case .issuancePending(let transactionId):
        throw ValidationError.error(reason: "Credential not ready yet. Try after \(transactionId.interval ?? 0)")
      case .errored(_, let errorDescription):
        throw ValidationError.error(reason: "\(errorDescription ?? "Something went wrong with your deferred request response")")
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
