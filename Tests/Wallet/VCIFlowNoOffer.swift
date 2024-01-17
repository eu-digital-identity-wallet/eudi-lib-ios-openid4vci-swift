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

class VCIFlowNoOffer: XCTestCase {
  
  override func setUp() async throws {
    try await super.setUp()
  }
  
  override func tearDown() {
    super.tearDown()
  }
  
  func testWebPageFormSubmission() async throws {

    _ = try await WebpageHelper().submit(
      formUrl: URL(string: "https://www.w3schools.com/html/html_forms.asp")!,
      username: "username",
      password: "password"
    )
  }
  
  func testNoOfferSdJWT() async throws {
    
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
      jwk: publicKeyJWK,
      privateKey: privateKey
    )
    
    let user = ActingUser(
      username: "tneal",
      password: "password"
    )
    
    let wallet = Wallet(
      actingUser: user,
      bindingKey: bindingKey
    )
    
    do {
      try await walletInitiatedIssuanceNoOfferSdJwt(wallet: wallet)
      
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(true)
  }
  
  func testNoOfferMdoc() async throws {
    
    let privateKey = try KeyController.generateECDHPrivateKey()
    let publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
    
    let alg = JWSAlgorithm(.ES256)
    let publicKeyJWK = try ECPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "alg": alg.name,
        "use": "sig",
        "kid": UUID().uuidString
      ])
    
    let bindingKey: BindingKey = .jwk(
      algorithm: alg,
      jwk: publicKeyJWK,
      privateKey: privateKey
    )
    
    let user = ActingUser(
      username: "tneal",
      password: "password"
    )
    
    let wallet = Wallet(
      actingUser: user,
      bindingKey: bindingKey
    )
    
    do {
      try await walletInitiatedIssuanceNoOfferMdoc(wallet: wallet)
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(true)
  }
}

private func walletInitiatedIssuanceNoOfferSdJwt(wallet: Wallet) async throws {
  
  print("[[Scenario: No offer passed, wallet initiates issuance by credetial scopes]]")
  
  let credential = try await wallet.issueByCredentialIdentifier(PID_SdJwtVC_SCOPE)
  
  print("--> [ISSUANCE] Issued PID in format \(PID_SdJwtVC_SCOPE): \(credential)")
}

private func walletInitiatedIssuanceNoOfferMdoc(wallet: Wallet) async throws {
  
  print("[[Scenario: No offer passed, wallet initiates issuance by credetial scopes]]")
  
  let credential = try await wallet.issueByCredentialIdentifier(PID_MsoMdoc_SCOPE)
  
  print("--> [ISSUANCE] Issued PID in format \(PID_MsoMdoc_SCOPE): \(credential)")
}
