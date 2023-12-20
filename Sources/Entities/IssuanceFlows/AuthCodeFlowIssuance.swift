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

public enum AuthCodeFlowIssuance {
  // State denoting that the pushed authorization request has been placed successfully and response processed
  case parRequested(getAuthorizationCodeURL: GetAuthorizationCodeURL, pkceVerifier: PKCEVerifier, state: String)
  
  // State denoting that the caller has followed the URL and response received from the authorization server and processed successfully
  case authorized(authorizationCode: IssuanceAuthorization, pkceVerifier: PKCEVerifier)
  
  // State denoting that the access token was requested from the authorization server and response received and processed successfully
  case accessTokenRetrieved(token: IssuanceAccessToken)
  
  // State denoting that the certificate issuance was requested and certificate issued and received successfully
  case issued(issuedAt: Date, certificate: IssuedCertificate)
}

