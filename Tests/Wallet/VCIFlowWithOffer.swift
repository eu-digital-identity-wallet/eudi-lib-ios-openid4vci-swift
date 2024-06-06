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

class VCIFlowWithOffer: XCTestCase {
  
  override func setUp() async throws {
    try await super.setUp()
  }
  
  override func tearDown() {
    super.tearDown()
  }
  
  func testWithOfferSdJWT() async throws {
    
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
      bindingKey: bindingKey, 
      dPoPConstructor: nil
    )
    
    do {
      try await walletInitiatedIssuanceWithOfferSdJWT(
        wallet: wallet
      )
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
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
      bindingKey: bindingKey,
      dPoPConstructor: nil
    )
    
    do {
      try await walletInitiatedIssuanceWithOfferMdoc(
        wallet: wallet
      )
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(true)
  }
  
  func testWithOfferMDL() async throws {
    
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
      bindingKey: bindingKey,
      dPoPConstructor: nil
    )
    
    do {
      try await walletInitiatedIssuanceWithOfferMDL(
        wallet: wallet
      )
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(true)
  }
  
  func testWithOfferMdocAndSdJwt() async throws {
    
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
      bindingKey: bindingKey,
      dPoPConstructor: nil
    )
    
    do {
      try await walletInitiatedIssuanceWithOfferArray(
        wallet: wallet
      )
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(true)
  }
  
  func testWithCredentialOfferURL() async throws {
    
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
      bindingKey: bindingKey,
      dPoPConstructor: nil
    )
    
    do {
      try await walletInitiatedIssuanceWithOfferUrl(
        wallet: wallet,
        url: CREDENTIAL_OFFER_QR_CODE_URL.removingPercentEncoding!
      )
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(true)
  }
  
  func testWithOfferMDLDPoP() async throws {
    
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
      bindingKey: bindingKey,
      dPoPConstructor: DPoPConstructor(
        algorithm: alg,
        jwk: publicKeyJWK,
        privateKey: privateKey
      )
    )
    
    do {
      try await walletInitiatedIssuanceWithOfferMDL_DPoP(
        wallet: wallet
      )
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(true)
  }
}

private func walletInitiatedIssuanceWithOfferSdJWT(
  wallet: Wallet,
  claimSet: ClaimSet? = nil
) async throws {
  
  print("[[Scenario: Offer passed to wallet via url]] ")
  
  let url = "\(CREDENTIAL_ISSUER_PUBLIC_URL)/credentialoffer?credential_offer=\(SdJwtVC_CredentialOffer)"
  let credential = try await wallet.issueByCredentialOfferUrl(
    offerUri: url,
    scope: PID_SdJwtVC_config_id,
    claimSet: claimSet
  )

  print("--> [ISSUANCE] Issued credential: \(credential)")
}

private func walletInitiatedIssuanceWithOfferMDL(
  wallet: Wallet,
  claimSet: ClaimSet? = nil
) async throws {
  
  print("[[Scenario: Offer passed to wallet via url]] ")
  
  let url = "\(CREDENTIAL_ISSUER_PUBLIC_URL)/credentialoffer?credential_offer=\(MDL_CredentialOffer)"
  let credential = try await wallet.issueByCredentialOfferUrl(
    offerUri: url,
    scope: MDL_config_id,
    claimSet: claimSet
  )
  
  print("--> [ISSUANCE] Issued credential : \(credential)")
}

private func walletInitiatedIssuanceWithOfferMDL_DPoP(
  wallet: Wallet,
  claimSet: ClaimSet? = nil
) async throws {
  
  print("[[Scenario: Offer passed to wallet via url]] ")
  
  let url = "\(CREDENTIAL_ISSUER_PUBLIC_URL)/credentialoffer?credential_offer=\(MDL_CredentialOffer)"
  let credential = try await wallet.issueByCredentialOfferUrl_DPoP(
    offerUri: url,
    scope: MDL_config_id,
    claimSet: claimSet
  )
  
  print("--> [ISSUANCE] Issued credential : \(credential)")
}

private func walletInitiatedIssuanceWithOfferMdoc(
  wallet: Wallet,
  claimSet: ClaimSet? = nil
) async throws {
  
  print("[[Scenario: Offer passed to wallet via url]] ")
  
  let url = "\(CREDENTIAL_ISSUER_PUBLIC_URL)/credentialoffer?credential_offer=\(MsoMdoc_CredentialOffer)"
  let credential = try await wallet.issueByCredentialOfferUrl(
    offerUri: url,
    scope: PID_MsoMdoc_config_id,
    claimSet: claimSet
  )
  
  print("--> [ISSUANCE] Issued credential : \(credential)")
}

private func walletInitiatedIssuanceWithOfferArray(
  wallet: Wallet,
  claimSet: ClaimSet? = nil
) async throws {
  
  print("[[Scenario: Offer passed to wallet via url]] ")
  
  let url = "\(CREDENTIAL_ISSUER_PUBLIC_URL)/credentialoffer?credential_offer=\(All_Supported_CredentialOffer)"
  let credentials = try await wallet.issueByCredentialOfferUrlMultipleFormats(
    offerUri: url,
    claimSet: claimSet
  )
  
  print("--> [ISSUANCE] Issued credentials:")
  for credential in credentials {
    print("\t [\(credential.0)]: \(credential.1)")
  }
}

private func walletInitiatedIssuanceWithOfferUrl(
  wallet: Wallet,
  url: String,
  claimSet: ClaimSet? = nil
) async throws {
  
  guard !url.isEmpty else {
    XCTExpectFailure()
    XCTAssert(false, "No url provided")
    return
  }
  
  print("[[Scenario: Offer passed to wallet via url]] ")
  
  let credentials = try await wallet.issueByCredentialOfferUrlMultipleFormats(
    offerUri: url,
    claimSet: claimSet
  )
  
  print("--> [ISSUANCE] Issued credentials:")
  for credential in credentials {
    print("\t [\(credential.0)]: \(credential.1)")
  }
}
