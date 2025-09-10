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
  
  func testWebPageFormSubmission() async throws {

    _ = try await WebpageHelper().submit(
      formUrl: URL(string: "https://www.w3schools.com/html/html_forms.asp")!,
      username: "username",
      password: "password"
    )
  }
  
  func testNoOfferSdJWT() async throws {
    
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
      privateKey: .secKey(privateKey)
    )
    
    let user = ActingUser(
      username: "tneal",
      password: "password"
    )
    
    let wallet = Wallet(
      actingUser: user,
      bindingKeys: [bindingKey]
    )
    
    do {
      try await walletInitiatedIssuanceNoOfferSdJwt(
        wallet: wallet
      )
      
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(true)
  }
  
  func testNoOfferSdJWTDeferred() async throws {
    
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
      privateKey: .secKey(privateKey)
    )
    
    let user = ActingUser(
      username: "tneal",
      password: "password"
    )
    
    let wallet = Wallet(
      actingUser: user,
      bindingKeys: [bindingKey]
    )
    
    do {
      try await walletInitiatedIssuanceNoOfferSdJwt(
        wallet: wallet,
        id: PID_SdJwtVC_config_id_deferred
      )
      
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
      privateKey: .secKey(privateKey)
    )
    
    let user = ActingUser(
      username: "tneal",
      password: "password"
    )
    
    let wallet = Wallet(
      actingUser: user,
      bindingKeys: [bindingKey]
    )
    
    do {
      try await walletInitiatedIssuanceNoOfferMdoc(
        wallet: wallet
      )
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(true)
  }
  
  func testNoOfferMDL() async throws {
    
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
      privateKey: .secKey(privateKey)
    )
    
    let user = ActingUser(
      username: "tneal",
      password: "password"
    )
    
    let wallet = Wallet(
      actingUser: user,
      bindingKeys: [bindingKey]
    )
    
    do {
      try await walletInitiatedIssuanceNoOfferMDL(
        wallet: wallet
      )
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(true)
  }
  
  func testNoOfferMdocMultipleProofs() async throws {
    
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
      privateKey: .secKey(privateKey)
    )
    
    let user = ActingUser(
      username: "tneal",
      password: "password"
    )
    
    let wallet = Wallet(
      actingUser: user,
      bindingKeys: [bindingKey, bindingKey]
    )
    
    do {
      try await walletInitiatedIssuanceNoOfferMdoc(
        wallet: wallet
      )
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(true)
  }
  
  func testNoOfferSdJWTSingleProof() async throws {
    
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
      privateKey: .secKey(privateKey)
    )
    
    let user = ActingUser(
      username: "tneal",
      password: "password"
    )
    
    let wallet = Wallet(
      actingUser: user,
      bindingKeys: [bindingKey]
    )
    
    do {
      try await walletInitiatedIssuanceNoOfferSdJwt(
        wallet: wallet
      )
      
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(true)
  }
  
  func testNoOfferSdJWTClientAuthentication() async throws {
    
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
      privateKey: .secKey(privateKey)
    )
    
    let user = ActingUser(
      username: "tneal",
      password: "password"
    )
    
    let wallet = Wallet(
      actingUser: user,
      bindingKeys: [bindingKey]
    )
    
    do {
      try await walletInitiatedIssuanceNoOfferSdJwtClientAuthentication(
        wallet: wallet
      )
      
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(true)
  }
  
  func testSDJWT15() async throws {
    
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
      privateKey: .secKey(privateKey)
    )
    
    let user = ActingUser(
      username: "tneal",
      password: "password"
    )
    
    let wallet = Wallet(
      actingUser: user,
      bindingKeys: [bindingKey]
    )
    
    do {
      _ = try await wallet.issueByCredentialIdentifier(
        PID_SdJwtVC_config_id,
        config: clientConfig
      )
      
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(true)
  }
  
  func testMsoMdoc15() async throws {
    
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
      privateKey: .secKey(privateKey)
    )
    
    let user = ActingUser(
      username: "tneal",
      password: "password"
    )
    
    let wallet = Wallet(
      actingUser: user,
      bindingKeys: [bindingKey]
    )
    
    do {
      _ = try await wallet.issueByCredentialIdentifier(
        PID_MsoMdoc_config_id,
        config: clientConfig
      )
      
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(true)
  }
}

private func walletInitiatedIssuanceNoOfferSdJwtClientAuthentication(
  wallet: Wallet
) async throws {
  
  print(NO_OFFER_BASED_SCENARIO)
  
  let credential = try await wallet.issueByCredentialIdentifier(
    PID_SdJwtVC_config_id,
    config: attestationConfig
  )
  
  print("--> [ISSUANCE] Issued PID in format \(PID_SdJwtVC_config_id): \(credential)")
}

private func walletInitiatedIssuanceNoOfferSdJwt(
  wallet: Wallet,
  id: String? = nil
) async throws {
  
  print(NO_OFFER_BASED_SCENARIO)
  
  let credential = try await wallet.issueByCredentialIdentifier(
    PID_SdJwtVC_config_id,
    config: clientConfig
  )
  
  print("--> [ISSUANCE] Issued PID in format \(id ?? PID_SdJwtVC_config_id): \(credential)")
}

private func walletInitiatedIssuanceNoOfferMdoc(
  wallet: Wallet
) async throws {
  
  print(NO_OFFER_BASED_SCENARIO)
  
  let credential = try await wallet.issueByCredentialIdentifier(
    PID_MsoMdoc_config_id,
    config: clientConfig
  )
  
  print("--> [ISSUANCE] Issued PID in format \(PID_MsoMdoc_config_id): \(credential)")
}

private func walletInitiatedIssuanceNoOfferMDL(wallet: Wallet) async throws {
  
  print(NO_OFFER_BASED_SCENARIO)
  
  let credential = try await wallet.issueByCredentialIdentifier(
    MDL_config_id,
    config: clientConfig
  )
  
  print("--> [ISSUANCE] Issued PID in format \(MDL_config_id): \(credential)")
}
