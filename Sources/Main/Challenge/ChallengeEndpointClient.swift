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

public protocol ChallengeEndpointClientType: Sendable {
  func getChallenge() async throws -> Nonce
}

public actor ChallengeEndpointClient: ChallengeEndpointClientType {
  
  public let challengeEndpoint: URL
  let poster: PostingType
  
  public init(
    poster: PostingType = Poster(),
    challengeEndpoint: URL
  ) {
    self.poster = poster
    self.challengeEndpoint = challengeEndpoint
  }
  
  public func getChallenge() async throws -> Nonce {

    var request = URLRequest(url: challengeEndpoint)
    request.httpMethod = HTTPMethod.POST.rawValue
    
    let result: Result<ResponseWithHeaders<ChallengeResponse>, Error> = await poster.post(
      request: request
    )
    
    switch result {
    case .success(let response):
      return Nonce(value: response.body.attestationChallenge)
    case .failure(let error):
      throw error
    }
  }
}

