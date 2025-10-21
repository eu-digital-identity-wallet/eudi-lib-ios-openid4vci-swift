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
import XCTest

@testable import OpenID4VCI

final class ChallengeEndpointClientTests: XCTestCase {
  
  func test_getChallenge_success_withNetworkingMock() async throws {
    let poster = Poster(
      session: NetworkingMock(
        path: "attestation_challenge",
        extension: "json"
      )
    )
    let endpoint = URL(string: "https://example.com/challenge")!
    let sut = ChallengeEndpointClient(poster: poster, challengeEndpoint: endpoint)
    
    let result = try await sut.getChallenge()
    
    switch result {
    case .success(let nonce):
      XCTAssertEqual(nonce.value, "my.attestation.challenge")
    case .failure(let error):
      XCTFail("Expected success, got error: \(error)")
    }
  }
}
