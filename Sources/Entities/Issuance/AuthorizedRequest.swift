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

public enum AuthorizedRequest {
  case noProofRequired(
    accessToken: IssuanceAccessToken,
    refreshToken: IssuanceRefreshToken?,
    credentialIdentifiers: AuthorizationDetailsIdentifiers?
    )
  case proofRequired(
    accessToken: IssuanceAccessToken,
    refreshToken: IssuanceRefreshToken?,
    cNonce: CNonce,
    credentialIdentifiers: AuthorizationDetailsIdentifiers?
  )
  
  public var noProofToken: IssuanceAccessToken? {
    switch self {
    case .noProofRequired(let accessToken, _, _):
      return accessToken
    case .proofRequired:
      return nil
    }
  }
  
  public var proofToken: IssuanceAccessToken? {
    switch self {
    case .noProofRequired:
      return nil
    case .proofRequired(let accessToken, _, _, _):
      return accessToken
    }
  }
}

public extension AuthorizedRequest {
  var accessToken: IssuanceAccessToken? {
    switch self {
    case .noProofRequired(let accessToken, _, _):
      return accessToken
    case .proofRequired(let accessToken, _, _, _):
      return accessToken
    }
  }
  
  func handleInvalidProof(cNonce: CNonce) throws -> AuthorizedRequest {
    switch self {
      
    case .noProofRequired(let accessToken, let refreshToken, let credentialIdentifiers):
      return .proofRequired(
        accessToken: accessToken,
        refreshToken: refreshToken,
        cNonce: cNonce,
        credentialIdentifiers: credentialIdentifiers
      )
    default: throw ValidationError.error(reason: "Expected .noProofRequired authorisation request")
    }
  }
}
