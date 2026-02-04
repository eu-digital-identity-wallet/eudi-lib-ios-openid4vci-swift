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
@preconcurrency import JOSESwift

@testable import OpenID4VCI

class VCIFlowNoOffer: XCTestCase {
  
  override func tearDown() async throws {
    let cookieStorage = HTTPCookieStorage.shared
    cookieStorage.cookies?.forEach { cookieStorage.deleteCookie($0) }
    URLCache.shared.removeAllCachedResponses()
  }
  
  func testWebPageFormSubmission() async throws {

    _ = try await WebpageHelper(Wallet.walletSession).submit(
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
    
    let bindingKey: BindingKey = .jwt(
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
    
    let bindingKey: BindingKey = .jwt(
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
        config: preferSignedClientConfig
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
    
    let bindingKey: BindingKey = .jwt(
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
        config: requireSignedClientConfig
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
    
    let bindingKey: BindingKey = .jwt(
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
    
    let bindingKey: BindingKey = .jwt(
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
    
    let bindingKey: BindingKey = .jwt(
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
    
    let bindingKey: BindingKey = .jwt(
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
    
    let bindingKey: BindingKey = .jwt(
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
    
    let bindingKey: BindingKey = .jwt(
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
  
  func testNoOfferJWSJSONSdJWTKeyAttestation() async throws {
    
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
    
    let algorithm = JWSAlgorithm(.ES256)
    let bindingKey: BindingKey = try! .jwtKeyAttestation(
      algorithm: algorithm,
      keyAttestationJWT: { nonce in
        
        let client = WalletProviderClient(
          baseURL: .init(
            string: "https://dev.wallet-provider.eudiw.dev"
          )!
        )
        
        let jwt = try await client.issueWalletUnitAttestation(
          dictionary: [
          "nonce": nonce!,
          "jwkSet": [
            "keys": [
              publicKeyJWK.toDictionary()
            ]
          ]
        ]).walletUnitAttestation
        
        return try .init(
          jws: .init(
            compactSerialization: jwt
          )
        )
      },
      keyIndex: 0,
      privateKey: .secKey(privateKey),
      issuer: "wallet-dev"
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
        wallet: wallet,
        id: EHIC_JwsJson_config_id
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
    
    let bindingKey: BindingKey = .attestation(
      keyAttestationJWT: { @KeyAttester nonce in
        let client = WalletProviderClient(
          baseURL: .init(
            string: "https://dev.wallet-provider.eudiw.dev"
          )!
        )
        
        let jwt = try await client.issueWalletUnitAttestation(
          dictionary: [
          "nonce": nonce!,
          "jwkSet": [
            "keys": [
              publicKeyJWK.toDictionary()
            ]
          ]
        ]).walletUnitAttestation
        
        return try .init(
          jws: .init(
            compactSerialization: jwt
          )
        )
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
    
    do {
      try await walletInitiatedIssuanceNoOfferSdJwtClientAuthentication(
        wallet: wallet,
        id: EHIC_JwsCompact_config_id
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
    let publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
    
    let attestationConfig: OpenId4VCIConfig = await .init(
      client: try! jwkProviderSignedClient(
        client: client,
        clientId: "eudiw-abca",
        algorithm: .ES256,
        privateKey: privateKey
      ),
      authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!,
      authorizeIssuanceConfig: .favorScopes,
      clientAttestationPoPBuilder: DefaultClientAttestationPoPBuilder()
    )
    
    let publicKeyJWK = try ECPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "alg": "ES256",
        "use": "sig",
        "kid": UUID().uuidString
      ])
    
    let bindingKey: BindingKey = .jwt(
      algorithm: JWSAlgorithm(.ES256),
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
  config: OpenId4VCIConfig = clientConfig
) async throws {
  
  print(NO_OFFER_BASED_SCENARIO)
  
  let credential = try await wallet.issueByCredentialIdentifier(
    id ?? PID_SdJwtVC_config_id,
    config: config
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
