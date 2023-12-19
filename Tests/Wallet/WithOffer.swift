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

class WithOffer: XCTestCase {
  
  override func setUp() async throws {
    try await super.setUp()
  }
  
  override func tearDown() {
    super.tearDown()
  }
  
  func testWithOfferSdJWT() async throws {
    
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
      try await walletInitiatedIssuanceWithOfferSdJWT(wallet: wallet)
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false)
    }
    
    XCTAssert(true)
  }
  
  func testWithOfferMdoc() async throws {
    
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
      try await walletInitiatedIssuanceWithOfferMdoc(wallet: wallet)
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false)
    }
    
    XCTAssert(true)
  }
}

private func walletInitiatedIssuanceWithOfferSdJWT(wallet: Wallet) async throws {
  
  print("[[Scenario: Offer passed to wallet via url]] ")
  
  let url = "\(CredentialIssuer_URL)/credentialoffer?credential_offer=\(SdJwtVC_CredentialOffer)"
  let credential = try await wallet.issueByCredentialOfferUrl(url: url)
  
  print("--> Issued credential: \(credential)")
}

private func walletInitiatedIssuanceWithOfferMdoc(wallet: Wallet) async throws {
  
  print("[[Scenario: Offer passed to wallet via url]] ")
  
  let url = "\(CredentialIssuer_URL)/credentialoffer?credential_offer=\(MsoMdoc_CredentialOffer)"
  let credential = try await wallet.issueByCredentialOfferUrl(url: url)
  
  print("--> Issued credential : \(credential)")
}

private func walletInitiatedIssuanceWithOfferArray(wallet: Wallet) async throws {
  
  print("[[Scenario: Offer passed to wallet via url]] ")
  
  let url = "\(CredentialIssuer_URL)/credentialoffer?credential_offer=\(All_Supported_CredentialOffer)"
  let credential = try await wallet.issueByCredentialOfferUrl(url: url)
  
  print("--> Issued credential : \(credential)")
}
