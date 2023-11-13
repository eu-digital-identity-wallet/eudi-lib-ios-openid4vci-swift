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
import JOSESwift

@testable import OpenID4VCI

let CredentialIssuer_URL = "http://localhost:8080"
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

struct ActingUser {
  let username: String
  let password: String
}

class ExampleTest: XCTestCase {
  
  override func setUp() async throws {
    try await super.setUp()
  }
  
  override func tearDown() {
    super.tearDown()
  }
  
  func test() async throws {
    
    let privateKey = try KeyController.generateRSAPrivateKey()
    let publicKey = try KeyController.generateRSAPublicKey(from: privateKey)
    
    let alg = JWSAlgorithm(.RS256)
    let publicKeyJWK = try RSAPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "alg": alg.name,
        "use": "sig",
        "kid": UUID().uuidString
      ])
    
    let bindingKey: BindingKey = .jwk(
      algorithm: alg,
      jwk: publicKeyJWK
    )
    
    let user = ActingUser(
      username: "babis",
      password: "babis"
    )
    
    let wallet = Wallet(
      actingUser: user,
      bindingKey: bindingKey
    )
    
    try await walletInitiatedIssuanceNoOffer(wallet: wallet)
    try await walletInitiatedIssuanceWithOffer(wallet: wallet)
  }
}

private func walletInitiatedIssuanceWithOffer(wallet: Wallet) async throws {
  
  print("[[Scenario: Offer passed to wallet via url]] ")
  
  let url = "http://localhost:8080/credentialoffer?credential_offer=\(SdJwtVC_CredentialOffer)"
  let credential = try await wallet.issueByCredentialOfferUrl(url: url)
  
  print("--> Issued credential : \(credential)")
}

private func walletInitiatedIssuanceNoOffer(wallet: Wallet) async throws {
  
  print("[[Scenario: No offer passed, wallet initiates issuance by credetial scopes]]")
  
  let credential = try await wallet.issueByScope(PID_SdJwtVC_SCOPE)
  
  print("--> Issued credential : \(credential)")
}
