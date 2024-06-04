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
import JOSESwift
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
    
    let header = try JWSHeader(parameters: [
      "typ": "dpop+jwt",
      "alg": algorithm.name,
      "jwk": jwk.toDictionary()
    ])
    
    var dictionary: [String: Any] = [
      JWTClaimNames.issuedAt: Int(Date().timeIntervalSince1970.rounded()),
      JWTClaimNames.htm: Methods.post.rawValue,
      JWTClaimNames.htu: endpoint.absoluteString,
      JWTClaimNames.jwtId: String.randomBase64URLString(length: 20)
    ]
    
    if let data = accessToken?.data(using: .utf8) {
      let hashed = SHA256.hash(data: data)
      let hash = Data(hashed).base64URLEncodedString()
      dictionary["ath"] = hash
    }
    
    let payload = Payload(try dictionary.toThrowingJSONData())
    
    guard let signatureAlgorithm = SignatureAlgorithm(rawValue: algorithm.name) else {
      throw CredentialIssuanceError.cryptographicAlgorithmNotSupported
    }
    
    guard let signer = Signer(
      signingAlgorithm: signatureAlgorithm,
      key: privateKey
    ) else {
      throw ValidationError.error(reason: "Unable to create JWS signer")
    }
    
    let jws = try JWS(
      header: header,
      payload: payload,
      signer: signer
    )
    
    return jws.compactSerializedString
  }
}
