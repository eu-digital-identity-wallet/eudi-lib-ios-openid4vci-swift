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
    transactionId: TransactionId
  ) async throws -> Result<DeferredCredentialIssuanceResponse, Error>
}

public actor IssuanceRequester: IssuanceRequesterType {
  
  public let issuerMetadata: CredentialIssuerMetadata
  public let service: AuthorisationServiceType
  public let poster: PostingType
  
  public init(
    issuerMetadata: CredentialIssuerMetadata,
    service: AuthorisationServiceType = AuthorisationService(),
    poster: PostingType = Poster()
  ) {
    self.issuerMetadata = issuerMetadata
    self.service = service
    self.poster = poster
  }
  
  public func placeIssuanceRequest(
    accessToken: IssuanceAccessToken,
    request: SingleCredential
  ) async throws -> Result<CredentialIssuanceResponse, Error> {
    let endpoint = issuerMetadata.credentialEndpoint.url
    
    do {
      let authorizationHeader: [String: String] = accessToken.authorizationHeader
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
              // TODO: Decode SingleIssuanceSuccessResponse
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
              
              let jwe = try JWE(compactSerialization: string)
              guard let decrypter = Decrypter(
                keyManagementAlgorithm: keyManagementAlgorithm,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                decryptionKey: key
              ) else {
                return .failure(ValidationError.error(reason: "Could nit instantiate descypter"))
              }
              let payload = try jwe.decrypt(using: decrypter)
              let response = try JSONDecoder().decode(SingleIssuanceSuccessResponse.self, from: payload.data())
              return .success(try response.toDomain())
            }
            
          } catch {
            return .failure(ValidationError.error(reason: error.localizedDescription))
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
            
            let jwe = try JWE(compactSerialization: string)
            guard let decrypter = Decrypter(
              keyManagementAlgorithm: keyManagementAlgorithm,
              contentEncryptionAlgorithm: contentEncryptionAlgorithm,
              decryptionKey: key
            ) else {
              return .failure(ValidationError.error(reason: "Could nit instantiate descypter"))
            }
            let payload = try jwe.decrypt(using: decrypter)
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
      let authorizationHeader: [String: Any] = accessToken.authorizationHeader
      let encodedRequest: [String: JSON] = try request
        .map { try $0.toDictionary() }
        .reduce(into: [:]) { result, dictionary in
          result.merge(dictionary) { (_, new) in new }
        }
      let merged = authorizationHeader.merging(encodedRequest) { (_, new) in new }
      
      let response: BatchIssuanceSuccessResponse = try await service.formPost(
        poster: poster,
        url: endpoint,
        headers: [:],
        parameters: merged.convertToDictionaryOfStrings()
      )
      return .success(try response.toBatchIssuanceResponse())
      
    } catch {
      return .failure(ValidationError.error(reason: error.localizedDescription))
    }
  }
  
  public func placeDeferredCredentialRequest(
    accessToken: IssuanceAccessToken,
    transactionId: TransactionId
  ) async throws -> Result<DeferredCredentialIssuanceResponse, Error> {
    guard let deferredCredentialEndpoint = issuerMetadata.deferredCredentialEndpoint else {
      throw CredentialError.issuerDoesNotSupportDeferredIssuance
    }
    
    let authorizationHeader: [String: String] = accessToken.authorizationHeader
    let encodedRequest: [String: Any] = try JSON(transactionId.toDeferredRequestTO().toDictionary()).dictionaryValue
    
    do {
      let response: DeferredCredentialIssuanceResponse = try await service.formPost(
        poster: poster,
        url: deferredCredentialEndpoint.url,
        headers: authorizationHeader,
        body: encodedRequest
      )
      return .success(response)
    } catch {
      
      return .failure(error)
    }
    
  }
}

private extension SingleIssuanceSuccessResponse {
  func toSingleIssuanceResponse() throws -> CredentialIssuanceResponse {
    if let transactionId = transactionId {
      return CredentialIssuanceResponse(
        credentialResponses: [.deferred(transactionId: try .init(value: transactionId))],
        cNonce:  CNonce(value: cNonce!, expiresInSeconds: cNonceExpiresInSeconds)
      )
      
    } else if let credential = credential {
      return CredentialIssuanceResponse(
        credentialResponses: [.issued(format: format, credential: credential)],
        cNonce: CNonce(value: cNonce, expiresInSeconds: cNonceExpiresInSeconds)
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
          return CredentialIssuanceResponse.Result.issued(format: response.format, credential: credential)
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
