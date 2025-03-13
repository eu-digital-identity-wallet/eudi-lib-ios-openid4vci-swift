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
import CryptoKit
@preconcurrency import JOSESwift

/// A protocol defining the construction of a DPoP (Demonstrating Proof-of-Possession) JWT.
public protocol DPoPConstructorType: Sendable {
  /// Generates a DPoP JWT for a given endpoint.
  /// - Parameters:
  ///   - endpoint: The URL endpoint for which the JWT is being generated.
  ///   - accessToken: An optional access token to be included in the JWT.
  ///   - nonce: An optional nonce value to prevent replay attacks.
  /// - Returns: A DPoP JWT as a `String`.
  /// - Throws: An error if the JWT creation fails.
  func jwt(
    endpoint: URL,
    accessToken: String?,
    nonce: Nonce?
  ) async throws -> String
}

/// A concrete implementation of `DPoPConstructorType`.
public final class DPoPConstructor: DPoPConstructorType {

  /// The type of the JWT token.
  static let type = "dpop+jwt"
  
  /// HTTP methods supported for JWT claims.
  private enum Methods: String {
    case get = "GET"
    case head = "HEAD"
    case post = "POST"
    case put = "PUT"
    case delete = "DELETE"
    case connect = "CONNECT"
    case options = "OPTIONS"
    case trace = "TRACE"
  }

  /// The cryptographic algorithm used for signing the JWT.
  public let algorithm: JWSAlgorithm
  
  /// The JSON Web Key (JWK) used for JWT verification.
  public let jwk: JWK
  
  /// The private key used for signing the JWT.
  public let privateKey: SigningKeyProxy

  /// Initializes a new `DPoPConstructor`.
  /// - Parameters:
  ///   - algorithm: The signing algorithm to use.
  ///   - jwk: The JWK used in the JWT header.
  ///   - privateKey: The private key for signing the JWT.
  public init(algorithm: JWSAlgorithm, jwk: JWK, privateKey: SigningKeyProxy) {
    self.algorithm = algorithm
    self.jwk = jwk
    self.privateKey = privateKey
  }

  /// Generates a DPoP JWT for the given endpoint.
  /// - Parameters:
  ///   - endpoint: The URL for which the JWT is being generated.
  ///   - accessToken: An optional access token to be included in the JWT.
  ///   - nonce: An optional nonce value to mitigate replay attacks.
  /// - Returns: A signed DPoP JWT as a `String`.
  /// - Throws: An error if JWT creation fails.
  public func jwt(
    endpoint: URL,
    accessToken: String?,
    nonce: Nonce?
  ) async throws -> String {

    let header = try JWSHeader(parameters: [
      JWTClaimNames.type: Self.type,
      JWTClaimNames.algorithm: algorithm.name,
      JWTClaimNames.JWK: jwk.toDictionary()
    ])

    var dictionary: [String: Any] = [
      JWTClaimNames.issuedAt: Int(Date().timeIntervalSince1970.rounded()),
      JWTClaimNames.htm: Methods.post.rawValue,
      JWTClaimNames.htu: endpoint.absoluteString,
      JWTClaimNames.jwtId: String.randomBase64URLString(length: 20)
    ]
    
    // Add nonce if available
    nonce.map { dictionary[JWTClaimNames.nonce] = $0.value }

    // Compute the access token hash if provided
    if let data = accessToken?.data(using: .utf8) {
      let hashed = SHA256.hash(data: data)
      let hash = Data(hashed).base64URLEncodedString()
      dictionary[JWTClaimNames.ath] = hash
    }

    let payload = Payload(try dictionary.toThrowingJSONData())

    guard let signatureAlgorithm = SignatureAlgorithm(rawValue: algorithm.name) else {
      throw CredentialIssuanceError.cryptographicAlgorithmNotSupported
    }

    // Create a signer for the JWT
    let signer = try await BindingKey.createSigner(
      with: header,
      and: payload,
      for: privateKey,
      and: signatureAlgorithm
    )
    
    let jws = try JWS(
      header: header,
      payload: payload,
      signer: signer
    )

    return jws.compactSerializedString
  }
}
