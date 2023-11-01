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

public protocol AuthorizeIssuance {
  
  /// Authorized Code Flow transitions
  func pushAuthorizationCodeRequest(credentials: [CredentialMetadata], issuerState: String?) async throws -> Result<ParRequested, Error>
  func handleAuthorizationCode(_ authorizationCode: IssuanceAuthorization) async throws -> Result<AuthorizationCodeRetrieved, Error>
  func requestAccessToken() async throws -> AuthorizedRequest
  
  /// Pre-Authorized Code Flow
  func authorizeWithPreAuthorizationCode(credentials: [CredentialMetadata], authorizationCode: IssuanceAuthorization) async throws -> AuthorizedRequest
}
