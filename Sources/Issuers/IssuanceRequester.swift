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
import JOSESwift

public protocol IssuanceRequesterType {
  
  var issuerMetadata: CredentialIssuerMetadata { get }
  
  func placeIssuanceRequest(
    accessToken: IssuanceAccessToken,
    request: SingleCredential
  ) async throws -> Result<CredentialIssuanceResponse, Error>
  
  func placeBatchIssuanceRequest(
    accessToken: IssuanceAccessToken,
    request: [SingleCredential]
  ) async throws -> Result<CredentialIssuanceResponse, Error>
  
  func placeDeferredCredentialRequest(
    accessToken: IssuanceAccessToken,
    transactionId: TransactionId,
    issuanceResponseEncryptionSpec: IssuanceResponseEncryptionSpec?
  ) async throws -> Result<DeferredCredentialIssuanceResponse, Error>
  
  func notifyIssuer(
    accessToken: IssuanceAccessToken?,
    notification: NotificationObject
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
    request: SingleCredential
  ) async throws -> Result<CredentialIssuanceResponse, Error> {
    let endpoint = issuerMetadata.credentialEndpoint.url
    
    do {
      let authorizationHeader: [String: String] = try accessToken.dPoPOrBearerAuthorizationHeader(
        dpopConstructor: dpopConstructor,
        endpoint: endpoint
      )
      
      let encodedRequest: [String: Any] = try request.toDictionary().dictionaryValue
      
      let response: SingleIssuanceSuccessResponse = try await service.formPost(
        poster: poster,
        url: endpoint,
        headers: authorizationHeader,
        body: encodedRequest
      )
      
      return .success(try response.toSingleIssuanceResponse())
      
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
  
  public func placeBatchIssuanceRequest(
    accessToken: IssuanceAccessToken,
    request: [SingleCredential]
  ) async throws -> Result<CredentialIssuanceResponse, Error> {
    guard
      let endpoint = issuerMetadata.batchCredentialEndpoint?.url
    else {
      throw CredentialIssuanceError.issuerDoesNotSupportBatchIssuance
    }
    
    do {
      let authorizationHeader: [String: Any] = try accessToken.dPoPOrBearerAuthorizationHeader(
        dpopConstructor: dpopConstructor,
        endpoint: endpoint
      )
      
      let encodedRequest: [JSON] = try request
        .map { try $0.toDictionary() }

      let merged = authorizationHeader.merging(["credential_requests": encodedRequest]) { (_, new) in new }
      
      let response: BatchIssuanceSuccessResponse = try await service.formPost(
        poster: poster,
        url: endpoint,
        headers: [:],
        body: merged
      )
      return .success(try response.toBatchIssuanceResponse())
      
    } catch {
      return .failure(ValidationError.error(reason: error.localizedDescription))
    }
  }
  
  public func placeDeferredCredentialRequest(
    accessToken: IssuanceAccessToken,
    transactionId: TransactionId,
    issuanceResponseEncryptionSpec: IssuanceResponseEncryptionSpec?
  ) async throws -> Result<DeferredCredentialIssuanceResponse, Error> {
    guard let deferredCredentialEndpoint = issuerMetadata.deferredCredentialEndpoint else {
      throw CredentialError.issuerDoesNotSupportDeferredIssuance
    }
    
    let authorizationHeader: [String: String] = try accessToken.dPoPOrBearerAuthorizationHeader(
      dpopConstructor: dpopConstructor,
      endpoint: deferredCredentialEndpoint.url
    )
    
    let encodedRequest: [String: Any] = try JSON(transactionId.toDeferredRequestTO().toDictionary()).dictionaryValue
    
    do {
      let response: DeferredCredentialIssuanceResponse = try await service.formPost(
        poster: poster,
        url: deferredCredentialEndpoint.url,
        headers: authorizationHeader,
        body: encodedRequest
      )
      return .success(response)
      
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
    notification: NotificationObject
  ) async throws -> Result<Void, Error> {
    do {
      
      guard let accessToken else {
        throw ValidationError.error(reason: "Missing access token")
      }
      
      guard let notificationEndpoint = issuerMetadata.notificationEndpoint else {
        throw CredentialIssuerMetadataValidationError.invalidNotificationEndpoint
      }
      
      let endpoint = notificationEndpoint.url
      let authorizationHeader: [String: String] = try accessToken.dPoPOrBearerAuthorizationHeader(
        dpopConstructor: dpopConstructor,
        endpoint: endpoint
      )
      
      let payload = NotificationObject(
        id: notification.id,
        event: notification.event,
        eventDescription: notification.eventDescription
      )
      let encodedRequest: [String: Any] = JSON(payload.toDictionary()).dictionaryValue
      
      do {
        let _: EmptyResponse = try await service.formPost(
          poster: poster,
          url: endpoint,
          headers: authorizationHeader,
          body: encodedRequest
        )
        return .success(())
        
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
    if let credential = credential {
      return CredentialIssuanceResponse(
        credentialResponses: [.issued(format: format ?? "", credential: credential, notificationId: nil)],
        cNonce: CNonce(value: cNonce, expiresInSeconds: cNonceExpiresInSeconds)
      )
    } else if let transactionId = transactionId {
      return CredentialIssuanceResponse(
        credentialResponses: [.deferred(transactionId: try .init(value: transactionId))],
        cNonce:  CNonce(value: cNonce!, expiresInSeconds: cNonceExpiresInSeconds)
      )
      
    }
    throw CredentialIssuanceError.responseUnparsable("Got success response for issuance but response misses 'transaction_id' and 'certificate' parameters")
  }
}

private extension BatchIssuanceSuccessResponse {
  func toBatchIssuanceResponse() throws -> CredentialIssuanceResponse {
    func mapResults() throws -> [CredentialIssuanceResponse.Result] {
      return try credentialResponses.map { response in
        if let transactionId = response.transactionId {
          return CredentialIssuanceResponse.Result.deferred(transactionId: try .init(value: transactionId))
        } else if let credential = response.credential {
          return CredentialIssuanceResponse.Result.issued(format: nil, credential: credential, notificationId: nil)
        } else {
          throw CredentialIssuanceError.responseUnparsable("Got success response for issuance but response misses 'transaction_id' and 'certificate' parameters")
        }
      }
    }
    
    return CredentialIssuanceResponse(
      credentialResponses: try mapResults(),
      cNonce: CNonce(value: cNonce, expiresInSeconds: cNonceExpiresInSeconds)
    )
  }
}
