//
//  DeprecatedIssuing.swift
//  OpenID4VCI
//
//  Created by Jonathan Esposito on 17/02/2026.
//

@available(*, deprecated, message: "Use AuthorizationRequested and AuthorizationCodeRetrieved directly")
public enum AuthorizationRequestPrepared: Sendable {
    case prepared(AuthorizationRequested)
    case authorizationCode(AuthorizationCodeRetrieved)
}

public protocol DeprecatedIssuing {
    
    /// Old way to Initiate an authorization request using a credential offer.
    ///
    /// - Parameter credentialOffer: The credential offer containing necessary details for authorization.
    /// - Returns: A result containing either an `UnauthorizedRequest` if the request is successful or an `Error` otherwise.
    @available(*, deprecated, message: "Use prepareAuthorizationRequest returning AuthorizationRequested")
    func prepareAuthorizationRequest(
        credentialOffer: CredentialOffer
    ) async throws -> Result<AuthorizationRequestPrepared, Error>
    
    /// Authorizes a request using a pre-authorization code.
    ///
    /// - Parameters:
    ///   - credentialOffer: The credential offer used for authorization.
    ///   - authorizationCode: The pre-authorization code provided by the issuer.
    ///   - client: The client making the authorization request.
    ///   - transactionCode: An optional transaction code, if applicable.
    ///   - authorizationDetailsInTokenRequest: Additional authorization details for the token request.
    /// - Returns: A result containing either an `AuthorizedRequest` if authorization succeeds or an `Error` otherwise.
    @available(*, deprecated, message: "Use authorizeWithPreAuthorizationCode returning AuthorizedRequest")
    func authorizeWithPreAuthorizationCode(
        credentialOffer: CredentialOffer,
        authorizationCode: IssuanceAuthorization,
        client: Client,
        transactionCode: String?,
        authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest
    ) async throws -> Result<AuthorizedRequest, Error>
    
    /// Completes the authorization process using an authorization code.
    ///
    /// - Parameters:
    ///   - authorizationCode: The unauthorized request containing the authorization code.
    ///   - authorizationDetailsInTokenRequest: Additional authorization details for the token request.
    /// - Returns: A result containing either an `AuthorizedRequest` if successful or an `Error` otherwise.
    @available(*, deprecated, message: "Use authorizeWithAuthorizationCode accepting AuthorizationCodeRetrieved")
    func authorizeWithAuthorizationCode(
        request: AuthorizationRequestPrepared,
        authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest,
        grant: Grants
    ) async -> Result<AuthorizedRequest, Error>
    
    /// Handles the authorization code and updates the request status.
    ///
    /// - Parameters:
    ///   - parRequested: The unauthorized request that needs authorization.
    ///   - authorizationCode: The authorization code issued by the issuer.
    /// - Returns: A result containing either an updated `UnauthorizedRequest` or an `Error`.
    @available(*, deprecated, message: "Use handleAuthorizationCode accepting AuthorizationRequested as request and returning AuthorizationCodeRetrieved")
    func handleAuthorizationCode(
        request: AuthorizationRequestPrepared,
        authorizationCode: IssuanceAuthorization
    ) async -> Result<AuthorizationRequestPrepared, Error>
    
    /// Handles the provided authorization code and updates the authorization request state.
    ///
    /// - Parameters:
    ///   - request: The `AuthorizationRequestPrepared` object representing the state of the authorization request.
    ///   - code: The authorization code received from the authorization server. This parameter is passed as `inout`
    ///           in case it needs to be modified or consumed during processing.
    /// - Returns: A `Result` containing the potentially updated `AuthorizationRequestPrepared` on success,
    ///            or an `Error` if the code is invalid or the processing fails.
    @available(*, deprecated, message: "Use handleAuthorizationCode accepting AuthorizationRequested as request and returning AuthorizationCodeRetrieved")
    func handleAuthorizationCode(
        request: AuthorizationRequestPrepared,
        code: inout String
    ) async -> Result<AuthorizationRequestPrepared, Error>
    
    /// Requests credential issuance after authorization.
    ///
    /// - Parameters:
    ///   - request: The authorized request to proceed with credential issuance.
    ///   - bindingKeys: A list of binding keys used for secure binding of the credential.
    ///   - requestPayload: The payload required for the credential issuance.
    ///   - responseEncryptionSpecProvider: A closure providing the encryption specifications for the response.
    /// - Returns: A result containing either a `SubmittedRequest` if successful or an `Error` otherwise.
    @available(*, deprecated, message: "Use requestCredential returning SubmittedRequest instead of Result object")
    func requestCredential(
        request: AuthorizedRequest,
        bindingKeys: [BindingKey],
        requestPayload: IssuanceRequestPayload,
        responseEncryptionSpecProvider: @Sendable (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
    ) async throws -> Result<SubmittedRequest, Error>
    
    /// Requests a deferred credential issuance.
    ///
    /// - Parameters:
    ///   - request: The authorized request for credential issuance.
    ///   - transactionId: The transaction ID associated with the request.
    ///   - dPopNonce: An optional nonce for DPoP security.
    /// - Returns: A result containing either a `DeferredCredentialIssuanceResponse` if successful or an `Error` otherwise.
    @available(*, deprecated, message: "Use requestDeferredCredential returning DeferredCredentialIssuanceResponse instead of Result object")
    func requestDeferredCredential(
        request: AuthorizedRequest,
        transactionId: TransactionId,
        dPopNonce: Nonce?
    ) async throws -> Result<DeferredCredentialIssuanceResponse, Error>
    
    /// Sends a notification related to the credential issuance process.
    ///
    /// - Parameters:
    ///   - authorizedRequest: The authorized request linked to the notification.
    ///   - notificationId: The ID of the notification.
    ///   - dPopNonce: An optional nonce for DPoP security.
    /// - Returns: A result containing either `Void` if successful or an `Error` otherwise.
    @available(*, deprecated, message: "Use notify just throwing and not returning a Result object")
    func notify(
        authorizedRequest: AuthorizedRequest,
        notificationId: NotificationObject,
        dPopNonce: Nonce?
    ) async throws -> Result<Void, Error>
    
    /// Refreshes an authorized request.
    ///
    /// - Parameters:
    ///   - clientId: The ID of the client requesting a refresh.
    ///   - authorizedRequest: The existing authorized request to be refreshed.
    ///   - dPopNonce: An optional nonce for DPoP security.
    /// - Returns: A result containing either a new `AuthorizedRequest` if successful or an `Error` otherwise.
    @available(*, deprecated, message: "Use refresh returning AuthorizedRequest instead of Result object")
    func refresh(
        clientId: String,
        authorizedRequest: AuthorizedRequest,
        dPopNonce: Nonce?
    ) async -> Result<AuthorizedRequest, Error>
    
}

public extension Issuer {
    
    @available(*, deprecated, message: "Use prepareAuthorizationRequest returning AuthorizationRequested")
    func prepareAuthorizationRequest(
        credentialOffer: CredentialOffer
    ) async throws -> Result<AuthorizationRequestPrepared, Error> {
        do {
            return .success(.prepared(try await prepareAuthorizationRequest(credentialOffer: credentialOffer)))
        } catch {
            return .failure(error)
        }
    }
    
    @available(*, deprecated, message: "Use authorizeWithPreAuthorizationCode returning AuthorizedRequest")
    func authorizeWithPreAuthorizationCode(
        credentialOffer: CredentialOffer,
        authorizationCode: IssuanceAuthorization,
        client: Client,
        transactionCode: String?,
        authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest = .doNotInclude
    ) async -> Result<AuthorizedRequest, Error> {
        do {
            return .success(try await authorizeWithPreAuthorizationCode(credentialOffer: credentialOffer,
                                                                        authorizationCode: authorizationCode,
                                                                        client: client,
                                                                        transactionCode: transactionCode,
                                                                        authorizationDetailsInTokenRequest: authorizationDetailsInTokenRequest))
        } catch {
            return .failure(error)
        }
    }
    
    @available(*, deprecated, message: "Use authorizeWithAuthorizationCode accepting AuthorizationCodeRetrieved as request")
    func authorizeWithAuthorizationCode(
        request: AuthorizationRequestPrepared,
        authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest = .doNotInclude,
        grant: Grants
    ) async -> Result<AuthorizedRequest, Error> {
        switch request {
        case .prepared:
            return .failure(ValidationError.error(reason: ".authorizationCode case is required"))
        case .authorizationCode(let authorizationCodeRetrieved):
            do {
                return .success(try await authorizeWithAuthorizationCode(request: authorizationCodeRetrieved,
                                                            authorizationDetailsInTokenRequest: authorizationDetailsInTokenRequest,
                                                            grant: grant))
            } catch {
                return .failure(error)
            }
        }
    }
    
    @available(*, deprecated, message: "Use handleAuthorizationCode accepting AuthorizationRequested as request and returning AuthorizationCodeRetrieved")
    func handleAuthorizationCode(
        request: AuthorizationRequestPrepared,
        authorizationCode: IssuanceAuthorization
    ) async -> Result<AuthorizationRequestPrepared, Error> {
        switch request {
        case .prepared(let request):
            do {
                return .success(.authorizationCode(try await handleAuthorizationCode(request: request, authorizationCode: authorizationCode)))
            } catch {
                return .failure(error)
            }
        case .authorizationCode:
            return .failure(
                ValidationError.error(
                    reason: ".prepared is required"
                )
            )
        }
    }
    
    @available(*, deprecated, message: "Use handleAuthorizationCode accepting AuthorizationRequested as request and returning AuthorizationCodeRetrieved")
    func handleAuthorizationCode(
        request: AuthorizationRequestPrepared,
        code: inout String
    ) async -> Result<AuthorizationRequestPrepared, Error> {
        switch request {
        case .prepared(let request):
            do {
                return .success(.authorizationCode(try await handleAuthorizationCode(request: request, code: &code)))
            } catch {
                return .failure(error)
            }
        case .authorizationCode:
            return .failure(
                ValidationError.error(
                    reason: ".prepared is required"
                )
            )
        }
    }
    
    @available(*, deprecated, message: "Use requestCredential returning SubmittedRequest instead of Result object")
    func requestCredential(
        request: AuthorizedRequest,
        bindingKeys: [BindingKey],
        requestPayload: IssuanceRequestPayload,
        responseEncryptionSpecProvider: @Sendable (_ issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?
    ) async throws -> Result<SubmittedRequest, Error> {
        do {
            return .success(try await requestCredential(request: request,
                                        bindingKeys: bindingKeys,
                                        requestPayload: requestPayload,
                                        responseEncryptionSpecProvider: responseEncryptionSpecProvider))
        } catch {
            return .failure(error)
        }
    }
    
    @available(*, deprecated, message: "Use requestDeferredCredential returning DeferredCredentialIssuanceResponse instead of Result object")
    func requestDeferredCredential(
        request: AuthorizedRequest,
        transactionId: TransactionId,
        dPopNonce: Nonce?
    ) async throws -> Result<DeferredCredentialIssuanceResponse, Error> {
        do {
            return .success(try await requestDeferredCredential(request: request,
                                                                transactionId: transactionId,
                                                                dPopNonce: dPopNonce))
        } catch {
            return .failure(error)
        }
    }
    
    @available(*, deprecated, message: "Use notify just throwing and not returning a Result object")
    func notify(
        authorizedRequest: AuthorizedRequest,
        notificationId: NotificationObject,
        dPopNonce: Nonce?
    ) async throws -> Result<Void, Error> {
        do {
            return .success(try await notify(authorizedRequest: authorizedRequest,
                                             notificationId: notificationId,
                                             dPopNonce: dPopNonce))
        } catch {
            return .failure(error)
        }
    }
    
    @available(*, deprecated, message: "Use refresh returning AuthorizedRequest instead of Result object")
    func refresh(
        clientId: String,
        authorizedRequest: AuthorizedRequest,
        dPopNonce: Nonce? = nil
    ) async -> Result<AuthorizedRequest, Error> {
        do {
            return .success(try await refresh(clientId: clientId,
                                              authorizedRequest: authorizedRequest,
                                              dPopNonce: dPopNonce))
        } catch {
            return .failure(error)
        }
    }
    
}
