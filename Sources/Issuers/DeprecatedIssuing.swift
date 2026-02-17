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
    @available(*, deprecated, message: "use prepareAuthorizationRequest returning AuthorizationRequested")
    func prepareAuthorizationRequest(
        credentialOffer: CredentialOffer
    ) async throws -> Result<AuthorizationRequestPrepared, Error>
    
    /// Completes the authorization process using an authorization code.
    ///
    /// - Parameters:
    ///   - authorizationCode: The unauthorized request containing the authorization code.
    ///   - authorizationDetailsInTokenRequest: Additional authorization details for the token request.
    /// - Returns: A result containing either an `AuthorizedRequest` if successful or an `Error` otherwise.
    @available(*, deprecated, message: "use authorizeWithAuthorizationCode accepting AuthorizationCodeRetrieved")
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
    @available(*, deprecated, message: "use handleAuthorizationCode accepting AuthorizationRequested as request and returning AuthorizationCodeRetrieved")
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
    @available(*, deprecated, message: "use handleAuthorizationCode accepting AuthorizationRequested as request and returning AuthorizationCodeRetrieved")
    func handleAuthorizationCode(
        request: AuthorizationRequestPrepared,
        code: inout String
    ) async -> Result<AuthorizationRequestPrepared, Error>
    
}

extension Issuer {
    
    @available(*, deprecated, message: "use prepareAuthorizationRequest returning AuthorizationRequested")
    public func prepareAuthorizationRequest(
        credentialOffer: CredentialOffer
    ) async throws -> Result<AuthorizationRequestPrepared, Error> {
        do {
            let result: Result<AuthorizationRequested, Error> = try await prepareAuthorizationRequest(credentialOffer: credentialOffer)
            switch result {
            case .success(let success): return .success(.prepared(success))
            case .failure(let failure): return .failure(failure)
            }
        } catch {
            return .failure(error)
        }
    }
    
    @available(*, deprecated, message: "use authorizeWithAuthorizationCode accepting AuthorizationCodeRetrieved as request")
    public func authorizeWithAuthorizationCode(
        request: AuthorizationRequestPrepared,
        authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest = .doNotInclude,
        grant: Grants
    ) async -> Result<AuthorizedRequest, Error> {
        switch request {
        case .prepared:
            return .failure(ValidationError.error(reason: ".authorizationCode case is required"))
        case .authorizationCode(let authorizationCodeRetrieved):
            return await authorizeWithAuthorizationCode(request: authorizationCodeRetrieved,
                                                        authorizationDetailsInTokenRequest: authorizationDetailsInTokenRequest,
                                                        grant: grant)
        }
    }
    
    @available(*, deprecated, message: "use handleAuthorizationCode accepting AuthorizationRequested as request and returning AuthorizationCodeRetrieved")
    public func handleAuthorizationCode(
        request: AuthorizationRequestPrepared,
        authorizationCode: IssuanceAuthorization
    ) async -> Result<AuthorizationRequestPrepared, Error> {
        switch request {
        case .prepared(let request):
            let result = await handleAuthorizationCode(request: request, authorizationCode: authorizationCode)
            switch result {
            case .success(let success): return .success(.authorizationCode(success))
            case .failure(let failure): return .failure(failure)
            }
        case .authorizationCode:
            return .failure(
                ValidationError.error(
                    reason: ".prepared is required"
                )
            )
        }
    }
    
    @available(*, deprecated, message: "use handleAuthorizationCode accepting AuthorizationRequested as request and returning AuthorizationCodeRetrieved")
    public func handleAuthorizationCode(
        request: AuthorizationRequestPrepared,
        code: inout String
    ) async -> Result<AuthorizationRequestPrepared, Error> {
        switch request {
        case .prepared(let request):
            let result = await handleAuthorizationCode(request: request, code: &code)
            switch result {
            case .success(let success): return .success(.authorizationCode(success))
            case .failure(let failure): return .failure(failure)
            }
        case .authorizationCode:
            return .failure(
                ValidationError.error(
                    reason: ".prepared is required"
                )
            )
        }
    }
    
}
