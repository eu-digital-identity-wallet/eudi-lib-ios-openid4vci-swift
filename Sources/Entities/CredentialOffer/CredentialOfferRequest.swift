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

public enum CredentialOfferRequest {
  case passByValue(metaData: String)
  case fetchByReference(url: URL)
}

public extension CredentialOfferRequest {
  init(urlString: String) throws {
    
    guard let url = URL(string: urlString) else {
      throw CredentialOfferRequestError.nonParsableCredentialOfferEndpointUrl(reason: urlString)
    }
    
    let parameters = url.queryParameters
    if let byValue = parameters["credential_offer"],
      !byValue.isEmpty {
      self = .passByValue(metaData: byValue)
      return
    } else if let byReference = parameters["credential_offer_uri"],
      !byReference.isEmpty {
      if let reference = URL(string: byReference) {
        self = .fetchByReference(url: reference)
        return
      } else {
        throw CredentialOfferRequestValidationError.invalidCredentialOfferUri(byReference)
      }
    } else {
      self = .fetchByReference(url: url)
     }
  }
}
