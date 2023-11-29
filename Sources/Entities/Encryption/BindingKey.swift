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

public enum BindingKey {
  
  // JWK Binding Key
  case jwk(
    algorithm: JWSAlgorithm,
    jwk: JWK,
    privateKey: SecKey
  )
  
  // DID Binding Key
  case did(identity: String)
  
  // X509 Binding Key
  case x509(certificate: X509Certificate)
}

public extension BindingKey {
  
  func toSupportedProof(
    issuanceRequester: IssuanceRequesterType,
    credentialSpec: SupportedCredential,
    cNonce: String
  ) throws -> Proof {
    switch self {
    case .jwk(
      let algorithm,
      let jwk,
      let privateKey
    ):
      switch credentialSpec {
      case .msoMdoc(let spec):
        let suites = spec.cryptographicSuitesSupported.contains { $0 == algorithm.name }
        let bindings = spec.cryptographicBindingMethodsSupported.contains { $0  == .jwk }
        let proofs = spec.proofTypesSupported?.contains { $0 == .jwt } ?? false
        
        guard suites else {
          throw CredentialIssuanceError.cryptographicSuiteNotSupported
        }
        
        guard bindings else {
          throw CredentialIssuanceError.cryptographicBindingMethodNotSupported
        }
        
        guard proofs else {
          throw CredentialIssuanceError.proofTypeNotSupported
        }
        
        let aud = issuanceRequester.issuerMetadata.credentialIssuerIdentifier.url.absoluteString
        
        let header = try JWSHeader(parameters: [
          "typ": "openid4vci-proof+jwt",
          "alg": algorithm.name,
          "jwk": jwk
        ])
        
        let nonceKey = "nonce"
        let dictionary: [String: Any] = [
          JWTClaimNames.issuedAt: Int(Date().timeIntervalSince1970.rounded()),
          JWTClaimNames.audience: aud,
          nonceKey: cNonce
        ]
        
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
        
        return .jwt(jws.compactSerializedString)
        
//      case .scope(_):
//        <#code#>
//      case .w3CSignedJwt(_):
//        <#code#>
//      case .w3CJsonLdSignedJwt(_):
//        <#code#>
//      case .w3CJsonLdDataIntegrity(_):
//        <#code#>
//      case .sdJwtVc(_):
//        <#code#>
      default: break
      }
      break
    case .did(let identity):
      throw ValidationError.todo(reason: ".did(\(identity) not implemented")
    case .x509(let certificate):
      throw ValidationError.todo(reason: ".x509(\(certificate) not implemented")
    }
    throw ValidationError.error(reason: "TODO")
  }
}

private extension BindingKey {
  
}
