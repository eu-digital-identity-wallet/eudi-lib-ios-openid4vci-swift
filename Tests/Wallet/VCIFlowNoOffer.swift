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
@preconcurrency import Foundation
import XCTest
@preconcurrency import JOSESwift

@testable import OpenID4VCI

class VCIFlowNoOffer: XCTestCase {
  
  override func tearDown() async throws {
    let cookieStorage = HTTPCookieStorage.shared
    cookieStorage.cookies?.forEach { cookieStorage.deleteCookie($0) }
    URLCache.shared.removeAllCachedResponses()
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
    
    let bindingKey: BindingKey = .jwtKeyAttestation(
      algorithm: alg,
      keyAttestationJWT: { nonce in
        try await fetchKeyAttestationJWT(nonce: nonce, publicKeyJWK: publicKeyJWK)
      },
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
        config: attestationConfig
      )
      
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(true)
  }
  
  func testNoOfferSdJWTPreferSigned() async throws {
    
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
    
    let bindingKey: BindingKey = .jwtKeyAttestation(
      algorithm: alg,
      keyAttestationJWT: { nonce in
        try await fetchKeyAttestationJWT(nonce: nonce, publicKeyJWK: publicKeyJWK)
      },
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
        config: attestationConfig
      )
      
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(true)
  }
  
  func testNoOfferSdJWTRequireSigned() async throws {
    
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
    
    let bindingKey: BindingKey = .jwtKeyAttestation(
      algorithm: alg,
      keyAttestationJWT: { nonce in
        try await fetchKeyAttestationJWT(nonce: nonce, publicKeyJWK: publicKeyJWK)
      },
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
        config: attestationConfig
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
    
    let bindingKey: BindingKey = .jwtKeyAttestation(
      algorithm: alg,
      keyAttestationJWT: { nonce in
        try await fetchKeyAttestationJWT(nonce: nonce, publicKeyJWK: publicKeyJWK)
      },
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
        id: PID_SdJwtVC_config_id_deferred,
        config: attestationConfig
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
    
    let bindingKey: BindingKey = .jwtKeyAttestation(
      algorithm: alg,
      keyAttestationJWT: { nonce in
        try await fetchKeyAttestationJWT(nonce: nonce, publicKeyJWK: publicKeyJWK)
      },
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
        wallet: wallet,
        config: attestationConfig
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
    
    let bindingKey: BindingKey = .jwtKeyAttestation(
      algorithm: alg,
      keyAttestationJWT: { nonce in
        try await fetchKeyAttestationJWT(nonce: nonce, publicKeyJWK: publicKeyJWK)
      },
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
    
    let bindingKey: BindingKey = .jwtKeyAttestation(
      algorithm: alg,
      keyAttestationJWT: { nonce in
        try await fetchKeyAttestationJWT(nonce: nonce, publicKeyJWK: publicKeyJWK)
      },
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
    
    let bindingKey: BindingKey = .jwtKeyAttestation(
      algorithm: alg,
      keyAttestationJWT: { nonce in
        try await fetchKeyAttestationJWT(nonce: nonce, publicKeyJWK: publicKeyJWK)
      },
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
  
  func testNoOfferCompactSdJWTKeyAttestation() async throws {
    
    let privateKey = TestsConstants.keyAttestationPrivateKey
    let publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
    let alg = JWSAlgorithm(.ES256)
    let publicKeyJWK = try ECPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "alg": alg.name,
        "use": "sig",
        "kid": UUID().uuidString
      ])
    
    do {
      let bindingKey: BindingKey = .attestation(
        keyAttestationJWT: { @KeyAttester nonce in
          try await fetchKeyAttestationJWT(nonce: nonce, publicKeyJWK: publicKeyJWK)
        }
      )
      
      let user = ActingUser(
        username: "tneal",
        password: "password"
      )
      
      let wallet = Wallet(
        actingUser: user,
        bindingKeys: [bindingKey]
      )
      
      try await walletInitiatedIssuanceNoOfferSdJwtClientAuthentication(
        wallet: wallet,
        id: PID_SdJwtVC_config_id
      )
    } catch {
      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(true)
  }
  
  func testNoOfferWalletInstanceAttestedSdJWT() async throws {
    
    let client = WalletProviderClient(
      baseURL: .init(
        string: "https://dev.wallet-provider.eudiw.dev"
      )!
    )
    
    let privateKey = try KeyController.generateECDHPrivateKey()
    let provider = try await jwkProviderSignedClient(
      client: client,
      clientId: "eudiw-abca",
      algorithm: .ES256,
      privateKey: privateKey
    )
    do {
      let attestationConfig: OpenId4VCIConfig = .init(
        client: provider.client,
        authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!,
        authorizeIssuanceConfig: .favorScopes,
        clientAttestationPoPBuilder: DefaultClientAttestationPoPBuilder()
      )
      
      let bindingKey: BindingKey = .jwtKeyAttestation(
        algorithm: JWSAlgorithm(.ES256),
        keyAttestationJWT: { nonce in
          try await fetchKeyAttestationJWT(nonce: nonce, publicKeyJWK: provider.publicKey)
        },
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
      
      try await walletInitiatedIssuanceNoOfferSdJwt(
        wallet: wallet,
        config: attestationConfig
      )
    } catch {
      
      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }
    
    XCTAssert(true)
  }
}

private func walletInitiatedIssuanceNoOfferSdJwtClientAuthentication(
  wallet: Wallet,
  id: String = PID_SdJwtVC_config_id
) async throws {
  
  print(NO_OFFER_BASED_SCENARIO)
  
  let credential = try await wallet.issueByCredentialIdentifier(
    id,
    config: attestationConfig
  )
  
  print("--> [ISSUANCE] Issued PID in format \(id): \(credential)")
}

private func walletInitiatedIssuanceNoOfferSdJwt(
  wallet: Wallet,
  id: String? = nil,
  config: OpenId4VCIConfig = attestationConfig
) async throws {
  
  print(NO_OFFER_BASED_SCENARIO)
  
  let credential = try await wallet.issueByCredentialIdentifier(
    id ?? PID_SdJwtVC_config_id,
    config: config
  )
  
  print("--> [ISSUANCE] Issued PID in format \(id ?? PID_SdJwtVC_config_id): \(credential)")
}

private func walletInitiatedIssuanceNoOfferMdoc(
  wallet: Wallet,
  config: OpenId4VCIConfig
) async throws {
  
  print(NO_OFFER_BASED_SCENARIO)
  
  let credential = try await wallet.issueByCredentialIdentifier(
    PID_MsoMdoc_config_id,
    config: attestationConfig
  )
  
  print("--> [ISSUANCE] Issued PID in format \(PID_MsoMdoc_config_id): \(credential)")
}

private func walletInitiatedIssuanceNoOfferMDL(wallet: Wallet) async throws {
  
  print(NO_OFFER_BASED_SCENARIO)
  
  let credential = try await wallet.issueByCredentialIdentifier(
    MDL_config_id,
    config: attestationConfig
  )
  
  print("--> [ISSUANCE] Issued PID in format \(MDL_config_id): \(credential)")
}
