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
@preconcurrency import JOSESwift

@testable import OpenID4VCI

internal func jwkProviderSignedClient(
  client: WalletProviderClient,
  clientId: String,
  algorithm: SignatureAlgorithm = .ES256,
  privateKey: SecKey
) async throws -> Client {
  
  let publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
  let publicKeyJWK = try ECPublicKey(
    publicKey: publicKey,
    additionalParameters: [
      "alg": "ES256",
      "use": "sig",
      "kid": UUID().uuidString
    ])
  
  let attestation = try await client.issueWalletInstanceAttestation(
    payload: [
      "jwk": publicKeyJWK.toDictionary()
    ]
  )
  
  @Sendable func getSignerFrom(authServer: URL) -> SigningKeyProxy {
    .secKey(privateKey)
  }
  
  return try .attested(
    id: clientId,
    alg: .init(.ES256),
    jwk: publicKeyJWK,
    popJwtSpec: .init(
      signingAlgorithm: algorithm,
      duration: 300.0,
      typ: "oauth-client-attestation-pop+jwt"
    ),
    clientAttestationProvider: { authServer in
      return (
        try! .init(
          jws: .init(
            compactSerialization: attestation.walletInstanceAttestation
          )
        ),
        getSignerFrom(authServer: authServer)
      )
    }
  )
}

internal func jwkSetProviderSignedClient(
  client: WalletProviderClient,
  clientId: String,
  algorithm: SignatureAlgorithm = .ES256,
  privateKey: SecKey
) async throws -> Client {
  
  let publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
  let publicKeyJWK = try ECPublicKey(
    publicKey: publicKey,
    additionalParameters: [
      "alg": "ES256",
      "use": "sig",
      "kid": UUID().uuidString
    ])
  
  let attestation = try await client.issueWalletUnitAttestation(dictionary: [
      "jwkSet": [
        "keys": [
          publicKeyJWK.toDictionary()
        ]
      ]
    ]
  )
  
  @Sendable func getSignerFrom(authServer: URL) -> SigningKeyProxy {
    .secKey(privateKey)
  }
  
  return try .attested(
    id: clientId,
    alg: .init(.ES256),
    jwk: publicKeyJWK,
    popJwtSpec: .init(
      signingAlgorithm: algorithm,
      duration: 300.0,
      typ: "oauth-client-attestation-pop+jwt"
    ),
    clientAttestationProvider: { authServer in
      return (
        try! .init(
          jws: .init(
            compactSerialization: attestation.walletUnitAttestation
          )
        ),
        getSignerFrom(authServer: authServer)
      )
    }
  )
}

internal func selfSignedClient(
  clientId: String,
  algorithm: SignatureAlgorithm = .ES256,
  privateKey: SecKey
) throws -> Client {
  
  guard isECPrivateKey(privateKey) else {
    fatalError("Key shoulb be EC and private")
  }
  
  guard algorithm.isNotMacAlgorithm else {
    fatalError("MAC not supported")
  }
  
  let header: JWSHeader = try! .init(
    parameters: [
      "alg": algorithm.rawValue,
      "typ": "oauth-client-attestation+jwt"
    ]
  )
  
  let jwk: ECPublicKey = try! ECPublicKey(
    publicKey: try! KeyController.generateECDHPublicKey(
      from: privateKey
    )
  )
  
  let duration: TimeInterval = 300
  let now = Date().timeIntervalSince1970
  let exp = Date().addingTimeInterval(duration).timeIntervalSince1970
  let payload: Payload = try! .init([
    "iss": clientId,
    "aud": clientId,
    "sub": clientId,
    "iat": now,
    "exp": exp,
    "cnf": [
      "jwk": jwk.toDictionary()
    ]
  ].toThrowingJSONData())
  

  
  @Sendable func getSignerFrom(authServer: URL) -> SigningKeyProxy {
    .secKey(privateKey)
  }
  
  return try .attested(
    id: clientId,
    alg: .init(.ES256),
    jwk: jwk,
    popJwtSpec: .init(
      signingAlgorithm: algorithm,
      duration: duration,
      typ: "oauth-client-attestation-pop+jwt"
    ),
    clientAttestationProvider: { authServer in
      let proxy = getSignerFrom(authServer: authServer)
      let signer = Signer(
        signatureAlgorithm: algorithm,
        key: proxy
      )!
      
      return (
        try! .init(
          jws: .init(
            header: header,
            payload: payload,
            signer: signer
          )
        ),
        proxy
      )
    }
  )
}

func isECPrivateKey(_ secKey: SecKey) -> Bool {
  guard let attributes = SecKeyCopyAttributes(secKey) as? [CFString: Any] else {
    return false
  }
  
  let isPrivateKey = (attributes[kSecAttrKeyClass] as? String) == (kSecAttrKeyClassPrivate as String)
  let isECKey = (attributes[kSecAttrKeyType] as? String) == (kSecAttrKeyTypeEC as String)
  
  return isPrivateKey && isECKey
}
