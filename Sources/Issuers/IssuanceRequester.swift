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

protocol IssuanceRequesterType {
  
  var issuerMetadata: CredentialIssuerMetadata { get }
  
  func placeIssuanceRequest(
    accessToken: IssuanceAccessToken,
    request: SingleCredential
  ) async -> Result<CredentialIssuanceResponse, Error>
  
  func placeBatchIssuanceRequest(
    accessToken: IssuanceAccessToken,
    request: [SingleCredential]
  ) async throws -> Result<CredentialIssuanceResponse, Error>
  
  func placeDeferredCredentialRequest(
    accessToken: IssuanceAccessToken,
    request: DeferredCredentialRequest
  ) async throws -> Result<CredentialIssuanceResponse, Error>
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
  ) async -> Result<CredentialIssuanceResponse, Error> {
    let endpoint = issuerMetadata.credentialEndpoint.url
    
    do {
      let authorizationHeader: [String: Any] = accessToken.authorizationHeader
      let encodedRequest: [String: Any] = try JSONEncoder().encode(request).toDictionary()
      let merged = authorizationHeader.merging(encodedRequest) { (_, new) in new }
      
      let response: SingleIssuanceSuccessResponse = try await service.formPost(
        poster: poster,
        url: endpoint,
        parameters: merged.convertToDictionaryOfStrings()
      )
      
      if request.requiresEncryptedResponse() {
        return .failure(ValidationError.error(reason: "NOT IMPLEMENTED: Decrypt JWT, extract JWT claims and map them to IssuanceResponse"))
      }
      return .success(try response.toSingleIssuanceResponse())
      
    } catch {
      return .failure(ValidationError.error(reason: error.localizedDescription))
    }
  }
  
  func placeBatchIssuanceRequest(
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
      let encodedRequest: [String: Any] = try JSONEncoder().encode(request).toDictionary()
      let merged = authorizationHeader.merging(encodedRequest) { (_, new) in new }
      
      let response: BatchIssuanceSuccessResponse = try await service.formPost(
        poster: poster,
        url: endpoint,
        parameters: merged.convertToDictionaryOfStrings()
      )
      return .success(try response.toBatchIssuanceResponse())
      
    } catch {
      return .failure(ValidationError.error(reason: error.localizedDescription))
    }
  }
  
  func placeDeferredCredentialRequest(
    accessToken: IssuanceAccessToken,
    request: DeferredCredentialRequest
  ) async throws -> Result<CredentialIssuanceResponse, Error> {
    throw ValidationError.error(reason: "Integration with Deferred Credential Endpoint not yet implemented")
  }
}

private extension SingleIssuanceSuccessResponse {
  func toSingleIssuanceResponse() throws -> CredentialIssuanceResponse {
    if let transactionId = transactionId {
      return CredentialIssuanceResponse(
        credentialResponses: [.deferred(transactionId: transactionId)],
        cNonce:  CNonce(value: cNonce!, expiresInSeconds: cNonceExpiresInSeconds)
      )
      
    } else if let credential = credential {
      return CredentialIssuanceResponse(
        credentialResponses: [.complete(format: format, credential: credential)],
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
          return CredentialIssuanceResponse.Result.deferred(transactionId: transactionId)
        } else if let credential = response.credential {
          return CredentialIssuanceResponse.Result.complete(format: response.format, credential: credential)
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
