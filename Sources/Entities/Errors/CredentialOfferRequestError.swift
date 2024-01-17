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

public enum CredentialOfferRequestError: Error, LocalizedError {
  
  case genericError
  
  case emptyCredentialsError
  
  // The Credential Offer Endpoint URL could not be parsed.
  case nonParsableCredentialOfferEndpointUrl(reason: String)
  
  // The Credential Offer object could not be fetched.
  case unableToFetchCredentialOffer(reason: String)
  
  // The Credential Offer object could not be parsed.
  case nonParseableCredentialOffer(reason: String)
  
  // The metadata of the Credential Issuer could not be resolved.
  case unableToResolveCredentialIssuerMetadata(reason: String)
  
  // The metadata of the Authorization Server could not be resolved.
  case unableToResolveAuthorizationServerMetadata(reason: String)
  
  public var errorDescription: String? {
    switch self {
    case .genericError:
      return "CredentialOfferRequestError:error: genericError"
    case .emptyCredentialsError:
      return "CredentialOfferRequestError:error: emptyCredentialsError"
    case .nonParsableCredentialOfferEndpointUrl(let reason):
      return "CredentialOfferRequestError:error: \(reason)"
    case .unableToFetchCredentialOffer(let reason):
      return "CredentialOfferRequestError:error: \(reason)"
    case .nonParseableCredentialOffer(let reason):
      return "CredentialOfferRequestError:error: \(reason)"
    case .unableToResolveCredentialIssuerMetadata(let reason):
      return "CredentialOfferRequestError:error: \(reason)"
    case .unableToResolveAuthorizationServerMetadata(let reason):
      return "CredentialOfferRequestError:error: \(reason)"
    }
  }
}
