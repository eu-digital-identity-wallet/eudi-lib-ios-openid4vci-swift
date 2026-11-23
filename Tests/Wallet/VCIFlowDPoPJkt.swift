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

class VCIFlowDPoPJkt: XCTestCase {

  override func tearDown() async throws {
    let cookieStorage = HTTPCookieStorage.shared
    cookieStorage.cookies?.forEach { cookieStorage.deleteCookie($0) }
    URLCache.shared.removeAllCachedResponses()
  }

  func testNoOfferSdJWTWithPARAndDPoPJkt() async throws {

    let wallet = try makeWallet()

    do {
      try await walletInitiatedIssuanceNoOfferDPoPJkt(
        wallet: wallet,
        config: dpopJktConfig(parUsage: .required, bindingMethod: .dpopJkt)
      )

    } catch {

      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }

    XCTAssert(true)
  }

  func testNoOfferMdocWithPARAndDPoPJkt() async throws {

    let wallet = try makeWallet()

    do {
      try await walletInitiatedIssuanceNoOfferDPoPJkt(
        wallet: wallet,
        id: PID_MsoMdoc_config_id,
        config: dpopJktConfig(parUsage: .required, bindingMethod: .dpopJkt)
      )

    } catch {

      XCTExpectFailure()
      XCTAssert(false, error.localizedDescription)
    }

    XCTAssert(true)
  }

  // The dev authorization server only accepts PAR, so the non-PAR flow cannot be
  // completed end to end. These tests verify the `dpop_jkt` placed in the authorization URL instead.
  func testAuthorizationRequestWithoutPARContainsDPoPJkt() async throws {

    let wallet = try makeWallet()

    try await assertAuthorizationCodeURLDPoPJkt(
      wallet: wallet,
      config: dpopJktConfig(parUsage: .never, bindingMethod: .dpopJkt),
      expectedPresent: true
    )
  }

  func testAuthorizationRequestWithoutPARAndDPoPHeaderContainsDPoPJkt() async throws {

    let wallet = try makeWallet()

    try await assertAuthorizationCodeURLDPoPJkt(
      wallet: wallet,
      config: dpopJktConfig(parUsage: .never, bindingMethod: .dpopHeader),
      expectedPresent: true
    )
  }

  func testAuthorizationRequestWithoutPARAndNoBindingOmitsDPoPJkt() async throws {

    let wallet = try makeWallet()

    try await assertAuthorizationCodeURLDPoPJkt(
      wallet: wallet,
      config: dpopJktConfig(parUsage: .never, bindingMethod: .none),
      expectedPresent: false
    )
  }
}

private func makeWallet() throws -> Wallet {

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

  return Wallet(
    actingUser: user,
    bindingKeys: [bindingKey]
  )
}

private func dpopJktConfig(
  parUsage: ParUsage,
  bindingMethod: AuthorizationCodeDPoPBindingMethod
) -> OpenId4VCIConfig {
  .init(
    client: attestionClient,
    authFlowRedirectionURI: URL(string: "urn:ietf:wg:oauth:2.0:oob")!,
    authorizeIssuanceConfig: .favorScopes,
    parUsage: parUsage,
    authorizationCodeDPoPBindingMethod: bindingMethod,
    clientAttestationPoPBuilder: DefaultClientAttestationPoPBuilder()
  )
}

private func walletInitiatedIssuanceNoOfferDPoPJkt(
  wallet: Wallet,
  id: String = PID_SdJwtVC_config_id,
  config: OpenId4VCIConfig
) async throws {

  print(NO_OFFER_BASED_SCENARIO)
  print("--> [DPOP] PAR usage: \(config.parUsage), binding method: \(config.authorizationCodeDPoPBindingMethod)")

  let credential = try await wallet.issueByCredentialIdentifier(
    id,
    config: config
  )

  print("--> [ISSUANCE] Issued PID in format \(id): \(credential)")
}

/// Prepares a (non-PAR) authorization request against the dev issuer and checks
/// the `dpop_jkt` query parameter against the thumbprint of the DPoP key in use.
private func assertAuthorizationCodeURLDPoPJkt(
  wallet: Wallet,
  id: String = PID_SdJwtVC_config_id,
  config: OpenId4VCIConfig,
  expectedPresent: Bool,
  file: StaticString = #filePath,
  line: UInt = #line
) async throws {

  let credentialIssuerIdentifier = try CredentialIssuerId(CREDENTIAL_ISSUER_PUBLIC_URL)

  let resolver = CredentialIssuerMetadataResolver(
    fetcher: MetadataFetcher(rawFetcher: RawDataFetcher(session: wallet.session))
  )

  let issuerMetadata = try await resolver.resolve(
    source: .credentialIssuer(credentialIssuerIdentifier),
    policy: config.issuerMetadataPolicy
  ).get()

  guard let authorizationServer = issuerMetadata.authorizationServers?.first else {
    XCTFail("Invalid authorization server", file: file, line: line)
    return
  }

  let authServerMetadata = try await AuthorizationServerMetadataResolver(
    oidcFetcher: Fetcher(session: wallet.session),
    oauthFetcher: Fetcher(session: wallet.session)
  ).resolve(url: authorizationServer).get()

  let offer = try CredentialOffer(
    credentialIssuerIdentifier: credentialIssuerIdentifier,
    credentialIssuerMetadata: issuerMetadata,
    credentialConfigurationIdentifiers: [.init(value: id)],
    grants: .authorizationCode(.init(authorizationServer: authorizationServer)),
    authorizationServerMetadata: authServerMetadata
  )

  guard let dpopConstructor = try dpopConstructor(
    algorithms: authServerMetadata.dpopSigningAlgValuesSupported
  ) else {
    XCTFail("Authorization server does not advertise DPoP support", file: file, line: line)
    return
  }

  let issuer = try Issuer(
    authorizationServerMetadata: authServerMetadata,
    issuerMetadata: issuerMetadata,
    config: config,
    dpopConstructor: dpopConstructor,
    session: wallet.session
  )

  let prepared = try await issuer.prepareAuthorizationRequest(
    credentialOffer: offer,
    additionalAuthorizationParameters: [:]
  )

  let authorizationCodeURL = prepared.authorizationCodeURL.url
  print("--> [AUTHORIZATION] Get authorization code URL is: \(authorizationCodeURL)")

  let dpopJkt = URLComponents(url: authorizationCodeURL, resolvingAgainstBaseURL: false)?
    .queryItems?
    .first { $0.name == "dpop_jkt" }?
    .value

  if expectedPresent {
    XCTAssertEqual(dpopJkt, try dpopConstructor.jwkThumbprint(), file: file, line: line)
  } else {
    XCTAssertNil(dpopJkt, file: file, line: line)
  }
}
