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
import JSONWebAlgorithms
import JSONWebKey
import JSONWebSignature
import JSONWebToken
import CryptoKit

public protocol DPoPConstructorType {
  func jwt(endpoint: URL, accessToken: String?) throws -> String
}
  
public class DPoPConstructor: DPoPConstructorType {
  
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
  
  public let algorithm: JWSAlgorithm
  public let jwk: JWK
  public let privateKey: SecKey
  
  public init(algorithm: JWSAlgorithm, jwk: JWK, privateKey: SecKey) {
    self.algorithm = algorithm
    self.jwk = jwk
    self.privateKey = privateKey
  }
  
  public func jwt(endpoint: URL, accessToken: String?) throws -> String {
    let header = DefaultJWSHeaderImpl(
        algorithm: try algorithm.parseToJoseLibrary(),
        jwk: jwk,
        type: "dpop+jwt"
    )

    let jwt = try JWT.signed(
      claims: {
        IssuedAtClaim(value: Date())
        JWTIdentifierClaim(value: String.randomBase64URLString(length: 20))
        StringClaim(key: "htm", value: Methods.post.rawValue)
        StringClaim(key: "htu", value: endpoint.absoluteString)
        if let data = accessToken?.data(using: .utf8) {
          let hashed = SHA256.hash(data: data)
          let hash = Data(hashed).base64URLEncodedString()
          StringClaim(key: "ath", value: hash)
        }
      },
      protectedHeader: header,
      key: privateKey
    )

    return jwt.jwtString
  }
}
