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
import JOSESwift
@preconcurrency import SwiftyJSON

/// A protocol defining the behavior for requesting credential issuance from an issuer.
/// Conforming types must implement methods to place issuance requests, request deferred credentials,
/// and notifications.
///
/// This protocol is `Sendable`, making it safe for concurrent use.
///
public protocol IssuanceRequesterType: Sendable {
  
  /// Metadata about the credential issuer.
  var issuerMetadata: CredentialIssuerMetadata { get }
  
  /// Places a request for credential issuance.
  ///
  /// - Parameters:
  ///   - accessToken: The access token used to authorize the request.
  ///   - request: The credential request object containing issuance details.
  ///   - dPopNonce: An optional nonce for DPoP (Demonstrating Proof-of-Possession).
  ///   - retry: A flag indicating whether the request should be retried on failure.
  /// - Returns: A `Result` containing either a `CredentialIssuanceResponse` or an `Error`.
  /// - Throws: An error if the issuance request fails.
  func placeIssuanceRequest(
    accessToken: IssuanceAccessToken,
    request: SingleCredential,
    dPopNonce: Nonce?,
    retry: Bool
  ) async throws -> Result<CredentialIssuanceResponse, Error>
  
  /// Places a request for a deferred credential issuance.
  ///
  /// - Parameters:
  ///   - accessToken: The access token used to authorize the request.
  ///   - transactionId: The identifier for the issuance transaction.
  ///   - dPopNonce: An optional nonce for DPoP (Demonstrating Proof-of-Possession).
  ///   - retry: A flag indicating whether the request should be retried on failure.
  ///   - issuanceResponseEncryptionSpec: Optional encryption specifications for securing the response.
  /// - Returns: A `Result` containing either a `DeferredCredentialIssuanceResponse` or an `Error`.
  /// - Throws: An error if the deferred issuance request fails.
  func placeDeferredCredentialRequest(
    accessToken: IssuanceAccessToken,
    transactionId: TransactionId,
    dPopNonce: Nonce?,
    retry: Bool,
    issuanceResponseEncryptionSpec: IssuanceResponseEncryptionSpec?
  ) async throws -> Result<DeferredCredentialIssuanceResponse, Error>
  
  /// Sends a notification to the credential issuer.
  ///
  /// - Parameters:
  ///   - accessToken: An optional access token for authorization.
  ///   - notification: The notification object containing relevant details.
  ///   - dPopNonce: An optional nonce for DPoP (Demonstrating Proof-of-Possession).
  ///   - retry: A flag indicating whether the notification should be retried on failure.
  /// - Returns: A `Result` indicating success (`Void`) or an `Error`.
  /// - Throws: An error if the notification request fails.
  func notifyIssuer(
    accessToken: IssuanceAccessToken?,
    notification: NotificationObject,
    dPopNonce: Nonce?,
    retry: Bool
  ) async throws -> Result<Void, Error>
}

public actor IssuanceRequester: IssuanceRequesterType {
  
  public let issuerMetadata: CredentialIssuerMetadata
  public let service: AuthorisationServiceType
  public let poster: PostingType
  public let dpopConstructor: DPoPConstructorType?
  
  public init(
    issuerMetadata: CredentialIssuerMetadata,
    service: AuthorisationServiceType = AuthorisationService(),
    poster: PostingType,
    dpopConstructor: DPoPConstructorType? = nil
  ) {
    self.issuerMetadata = issuerMetadata
    self.service = service
    self.poster = poster
    self.dpopConstructor = dpopConstructor
  }
  
  public func placeIssuanceRequest(
    accessToken: IssuanceAccessToken,
    request: SingleCredential,
    dPopNonce: Nonce?,
    retry: Bool
  ) async throws -> Result<CredentialIssuanceResponse, Error> {
    let endpoint = issuerMetadata.credentialEndpoint.url
    
    do {
      let authorizationHeader: [String: String] = try await accessToken.dPoPOrBearerAuthorizationHeader(
        dpopConstructor: dpopConstructor,
        dPopNonce: dPopNonce,
        endpoint: endpoint
      )
      
      let encodedRequest: [String: any Sendable] = try request.toPayload().dictionaryValue
      
      let response: ResponseWithHeaders<SingleIssuanceSuccessResponse> = try await service.formPost(
        poster: poster,
        url: endpoint,
        headers: authorizationHeader,
        body: encodedRequest
      )
      
      return .success(try response.body.toSingleIssuanceResponse())
      
    } catch PostError.useDpopNonce(let nonce) {
      if retry {
        return try await placeIssuanceRequest(
          accessToken: accessToken,
          request: request,
          dPopNonce: nonce,
          retry: false
        )
      } else {
        return .failure(ValidationError.retryFailedAfterDpopNonce)
      }
      
    } catch PostError.response(let response) {
      return .failure(response.toIssuanceError())
      
    } catch PostError.cannotParse(let string) {
      switch request {
      case .msoMdoc(let credential):
        switch issuerMetadata.credentialResponseEncryption {
        case .notRequired:
          guard let response = SingleIssuanceSuccessResponse.fromJSONString(string) else {
            return .failure(ValidationError.todo(reason: "Cannot decode .notRequired response"))
          }
          return .success(try response.toDomain())
        case .required:
          do {
            guard let key = credential.credentialEncryptionKey else {
              return .failure(ValidationError.error(reason: "Invalid private key"))
            }
            
            switch credential.requestedCredentialResponseEncryption {
            case .notRequested:
              throw ValidationError.error(reason: "Issuer expects response encryption")
            case .requested(
              _,
              _,
              let responseEncryptionAlg,
              let responseEncryptionMethod
            ):
              
              guard
                let keyManagementAlgorithm = KeyManagementAlgorithm(algorithm: responseEncryptionAlg),
                let contentEncryptionAlgorithm = ContentEncryptionAlgorithm(encryptionMethod: responseEncryptionMethod)
              else {
                return .failure(ValidationError.error(reason: "Unsupported encryption algorithms: \(responseEncryptionAlg.name), \(responseEncryptionMethod.name)"))
              }
              
              let payload = try decrypt(
                jwtString: string,
                keyManagementAlgorithm: keyManagementAlgorithm,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                privateKey: key
              )
              
              let response = try JSONDecoder().decode(SingleIssuanceSuccessResponse.self, from: payload.data())
              return .success(try response.toDomain())
            }
            
          } catch {
            return .failure(error)
          }
        }
      case .sdJwtVc(let credential):
        switch issuerMetadata.credentialResponseEncryption {
        case .notRequired:
          guard let response = SingleIssuanceSuccessResponse.fromJSONString(string) else {
            return .failure(ValidationError.todo(reason: "Cannot decode .notRequired response"))
          }
          return .success(try response.toDomain())
        case .required:
          guard let key = credential.credentialEncryptionKey else {
            return .failure(ValidationError.error(reason: "Invalid private key"))
          }
          
          switch credential.requestedCredentialResponseEncryption {
          case .notRequested:
            throw ValidationError.error(reason: "Issuer expects response encryption")
          case .requested(
            _,
            _,
            let responseEncryptionAlg,
            let responseEncryptionMethod
          ):
            
            guard
              let keyManagementAlgorithm = KeyManagementAlgorithm(algorithm: responseEncryptionAlg),
              let contentEncryptionAlgorithm = ContentEncryptionAlgorithm(encryptionMethod: responseEncryptionMethod)
            else {
              return .failure(ValidationError.error(reason: "Unsupported encryption algorithms"))
            }
            
            let payload = try decrypt(
              jwtString: string,
              keyManagementAlgorithm: keyManagementAlgorithm,
              contentEncryptionAlgorithm: contentEncryptionAlgorithm,
              privateKey: key
            )
            let response = try JSONDecoder().decode(SingleIssuanceSuccessResponse.self, from: payload.data())
            return .success(try response.toDomain())
          }
        }
      }
      
    } catch {
      return .failure(ValidationError.error(reason: error.localizedDescription))
    }
  }
  
  public func placeDeferredCredentialRequest(
    accessToken: IssuanceAccessToken,
    transactionId: TransactionId,
    dPopNonce: Nonce?,
    retry: Bool,
    issuanceResponseEncryptionSpec: IssuanceResponseEncryptionSpec?
  ) async throws -> Result<DeferredCredentialIssuanceResponse, Error> {
    guard let deferredCredentialEndpoint = issuerMetadata.deferredCredentialEndpoint else {
      throw CredentialError.issuerDoesNotSupportDeferredIssuance
    }
    
    let authorizationHeader: [String: String] = try await accessToken.dPoPOrBearerAuthorizationHeader(
      dpopConstructor: dpopConstructor,
      dPopNonce: dPopNonce,
      endpoint: deferredCredentialEndpoint.url
    )
    
    let encodedRequest: [String: any Sendable] = try JSON(transactionId.toDeferredRequestTO().toDictionary()).dictionaryValue
    
    do {
      let response: ResponseWithHeaders<DeferredCredentialIssuanceResponse> = try await service.formPost(
        poster: poster,
        url: deferredCredentialEndpoint.url,
        headers: authorizationHeader,
        body: encodedRequest
      )
      return .success(response.body)
      
    } catch PostError.useDpopNonce(let nonce) {
      if retry {
        return try await placeDeferredCredentialRequest(
          accessToken: accessToken,
          transactionId: transactionId,
          dPopNonce: nonce,
          retry: false,
          issuanceResponseEncryptionSpec: issuanceResponseEncryptionSpec
        )
      } else {
        return .failure(ValidationError.retryFailedAfterDpopNonce)
      }
      
    } catch PostError.response(let response) {
      
      let issuanceError = response.toIssuanceError()
      
      if case .deferredCredentialIssuancePending = issuanceError {
        return .success(.issuancePending(transactionId: transactionId))
      }
      
      return .failure(issuanceError)
      
    } catch PostError.cannotParse(let string) {
      
      if let responseEncryptionSpec = issuanceResponseEncryptionSpec {
        guard
          let keyManagementAlgorithm = KeyManagementAlgorithm(algorithm: responseEncryptionSpec.algorithm),
          let contentEncryptionAlgorithm = ContentEncryptionAlgorithm(encryptionMethod: responseEncryptionSpec.encryptionMethod)
        else {
          return .failure(ValidationError.error(reason: "Unsupported encryption algorithms: \(responseEncryptionSpec.algorithm.name), \(responseEncryptionSpec.encryptionMethod.name)"))
        }
        
        guard let key = responseEncryptionSpec.privateKey else {
          return .failure(ValidationError.error(reason: "Invalid private key"))
        }
        
        let payload = try decrypt(
          jwtString: string,
          keyManagementAlgorithm: keyManagementAlgorithm,
          contentEncryptionAlgorithm: contentEncryptionAlgorithm,
          privateKey: key
        )
        
        let response = try JSONDecoder().decode(DeferredCredentialIssuanceResponse.self, from: payload.data())
        return .success(response)
      }
      
      return .failure(ValidationError.error(reason: "responseEncryptionSpec not found \(#line)"))
      
    } catch {
      
      return .failure(error)
    }
  }
  
  public func notifyIssuer(
    accessToken: IssuanceAccessToken?,
    notification: NotificationObject,
    dPopNonce: Nonce?,
    retry: Bool
  ) async throws -> Result<Void, Error> {
    do {
      
      guard let accessToken else {
        throw ValidationError.error(reason: "Missing access token")
      }
      
      guard let notificationEndpoint = issuerMetadata.notificationEndpoint else {
        throw CredentialIssuerMetadataValidationError.invalidNotificationEndpoint
      }
      
      let endpoint = notificationEndpoint.url
      let authorizationHeader: [String: String] = try await accessToken.dPoPOrBearerAuthorizationHeader(
        dpopConstructor: dpopConstructor,
        dPopNonce: dPopNonce,
        endpoint: endpoint
      )
      
      let payload = NotificationObject(
        id: notification.id,
        event: notification.event,
        eventDescription: notification.eventDescription
      )
      let encodedRequest: [String: any Sendable] = JSON(payload.toDictionary()).dictionaryValue
      
      do {
        let _: ResponseWithHeaders<EmptyResponse> = try await service.formPost(
          poster: poster,
          url: endpoint,
          headers: authorizationHeader,
          body: encodedRequest
        )
        return .success(())
        
      } catch PostError.useDpopNonce(let nonce) {
        if retry {
          return try await notifyIssuer(
            accessToken: accessToken,
            notification: notification,
            dPopNonce: nonce,
            retry: false
          )
        } else {
          return .failure(ValidationError.retryFailedAfterDpopNonce)
        }
        
      } catch PostError.response(let response) {
        return .failure(response.toIssuanceError())
        
      } catch {
        
        return .failure(error)
      }
      
    } catch {
      return .failure(error)
    }
  }
}

private extension IssuanceRequester {
  func decrypt(
    jwtString: String,
    keyManagementAlgorithm: KeyManagementAlgorithm,
    contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
    privateKey: SecKey
  ) throws -> Payload {
    
    let jwe = try JWE(compactSerialization: jwtString)
    guard let decrypter = Decrypter(
      keyManagementAlgorithm: keyManagementAlgorithm,
      contentEncryptionAlgorithm: contentEncryptionAlgorithm,
      decryptionKey: privateKey
    ) else {
      throw ValidationError.error(reason: "Could not instantiate descypter")
    }
    return try jwe.decrypt(using: decrypter)
  }
}

private extension SingleIssuanceSuccessResponse {
  func toSingleIssuanceResponse() throws -> CredentialIssuanceResponse {
    if let credential = credential,
       let string = credential.string {
      return CredentialIssuanceResponse(
        credentialResponses: [
          .issued(
            format: nil,
            credential: .string(string),
            notificationId: nil,
            additionalInfo: nil
          )
        ]
      )
    } else if let credentials = credentials,
       !credentials.isEmpty {
      return .init(
        credentialResponses: [
          .issued(
            format: nil,
            credential: .json(JSON(credentials)),
            notificationId: nil,
            additionalInfo: nil
          )
        ]
      )
    } else if let transactionId = transactionId {
      return CredentialIssuanceResponse(
        credentialResponses: [
          .deferred(transactionId: try .init(value: transactionId))
        ]
      )
      
    }
    throw CredentialIssuanceError.responseUnparsable("Got success response for issuance but response misses 'transaction_id' and 'certificate' parameters")
  }
}
