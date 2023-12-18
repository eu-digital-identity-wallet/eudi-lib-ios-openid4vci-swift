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
@testable import OpenID4VCI

//let CredentialIssuer_URL = "http://localhost:8080"
let CredentialIssuer_URL = "https://eudi.netcompany-intrasoft.com/pid-issuer"

let PID_SdJwtVC_SCOPE = "eu.europa.ec.eudiw.pid_vc_sd_jwt"
let PID_MsoMdoc_SCOPE = "eu.europa.ec.eudiw.pid_mso_mdoc"

let SdJwtVC_CredentialOffer = """
    {
      "credential_issuer": "\(CredentialIssuer_URL)",
      "credentials": [ "\(PID_SdJwtVC_SCOPE)" ],
      "grants": {
        "authorization_code": {}
      }
    }
"""

let MsoMdoc_CredentialOffer = """
    {
      "credential_issuer": "\(CredentialIssuer_URL)",
      "grants": {
        "authorization_code": {}
      },
      "credentials": [ "\(PID_MsoMdoc_SCOPE)" ]
    }
"""

let config: WalletOpenId4VCIConfig = .init(
  clientId: "wallet-dev",
  authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!
)

public struct ActingUser {
  public let username: String
  public let password: String
  
  public init(username: String, password: String) {
    self.username = username
    self.password = password
  }
}


struct TestsConstants {
  
  static let CREDENTIAL_ISSUER_PUBLIC_URL = "https://credential-issuer.example.com"
  static let AUTHORIZATION_SERVER_PUBLIC_URL = "https://as.example.com"
  
  static let AUTH_CODE_GRANT_CREDENTIAL_OFFER = """
  {
    "credential_issuer": "\(Self.CREDENTIAL_ISSUER_PUBLIC_URL)",
    "credentials": ["PID_mso_mdoc", "UniversityDegree"],
    "grants": {
      "authorization_code": {
        "issuer_state": "eyJhbGciOiJSU0EtFYUaBy"
      }
    }
  }
  """
  
  static let AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS = """
  {
    "credential_issuer": "\(Self.CREDENTIAL_ISSUER_PUBLIC_URL)",
    "credentials": ["PID_mso_mdoc", "UniversityDegree"]
  }
  """
  
  static let PRE_AUTH_CODE_GRANT_CREDENTIAL_OFFER = """
  {
    "credential_issuer": "\(Self.CREDENTIAL_ISSUER_PUBLIC_URL)",
    "credentials": ["PID_mso_mdoc", "UniversityDegree"],
    "grants": {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": "eyJhbGciOiJSU0EtFYUaBy",
        "user_pin_required": true
      }
    }
  }
  """
}
