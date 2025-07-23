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

public struct CNonceResponse: Codable, Sendable {
  let cNonce: String
  
  enum CodingKeys: String, CodingKey {
    case cNonce = "c_nonce"
  }
}

public protocol NonceEndpointClientType: Sendable {
  func getNonce() async throws -> Result<CNonceResponse, Error>
}

public actor NonceEndpointClient: NonceEndpointClientType {
  
  public let nonceEndpoint: CredentialIssuerEndpoint
  let poster: PostingType
  
  public init(
    poster: PostingType = Poster(),
    nonceEndpoint: CredentialIssuerEndpoint
  ) {
    self.poster = poster
    self.nonceEndpoint = nonceEndpoint
  }
  
  public func getNonce() async throws -> Result<CNonceResponse, Error> {

    var request = URLRequest(url: nonceEndpoint.url)
    request.httpMethod = HTTPMethod.POST.rawValue
    
    let result: Result<ResponseWithHeaders<CNonceResponse>, PostError> = await poster.post(
      request: request
    )
    
    switch result {
    case .success(let response):
      return .success(response.body)
    case .failure(let error):
      return .failure(error)
    }
  }
}
