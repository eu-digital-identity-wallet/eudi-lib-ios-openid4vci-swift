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

public enum BindingKey {
  
  // JWK Binding Key
  case jwk(
    algorithm: JWSAlgorithm,
    jwk: JWK,
    privateKey: KeyRepresentable,
    issuer: String? = nil
  )
  
  // DID Binding Key
  case did(identity: String)
  
  // X509 Binding Key
  case x509(certificate: X509Certificate)
}

public extension BindingKey {
  
  func toSupportedProof(
    issuanceRequester: IssuanceRequesterType,
    credentialSpec: CredentialSupported,
    cNonce: String?
  ) throws -> Proof {
    switch self {
    case .jwk(
      let algorithm,
      let jwk,
      let privateKey,
      let issuer
    ):
      switch credentialSpec {
      case .msoMdoc(let spec):
        let suites = spec.proofTypesSupported?["jwt"]?.algorithms.contains { $0 == algorithm.name } ??  true
        guard suites else {
          throw CredentialIssuanceError.cryptographicSuiteNotSupported(algorithm.name)
        }

        let proofs = spec.proofTypesSupported?.keys.contains { $0 == "jwt" } ?? true
        guard proofs else {
          throw CredentialIssuanceError.proofTypeNotSupported
        }
        
        let aud = issuanceRequester.issuerMetadata.credentialIssuerIdentifier.url.absoluteString
        let header = DefaultJWSHeaderImpl(
            algorithm: try algorithm.parseToJoseLibrary(),
            jwk: jwk,
            type: "openid4vci-proof+jwt"
        )

        let jwt = try JWT.signed(
          claims: {
            IssuedAtClaim(value: Date())
            AudienceClaim(value: aud)
            StringClaim(key: "nonce", value: cNonce ?? "")
            IssuerClaim(value: issuer ?? "")
          },
          protectedHeader: header,
          key: privateKey
        )

        return .jwt(jwt.jwtString)

      case .sdJwtVc(let spec):
        let suites = spec.proofTypesSupported?["jwt"]?.algorithms.contains { $0 == algorithm.name } ??  true
        guard suites else {
          throw CredentialIssuanceError.cryptographicSuiteNotSupported(algorithm.name)
        }

        let proofs = spec.proofTypesSupported?.keys.contains { $0 == "jwt" } ?? true
        guard proofs else {
          throw CredentialIssuanceError.proofTypeNotSupported
        }
        
        /*
        let bindings = spec.cryptographicBindingMethodsSupported.contains { $0  == .jwk }
        guard bindings else {
          throw CredentialIssuanceError.cryptographicBindingMethodNotSupported
        }
         */
        
        let aud = issuanceRequester.issuerMetadata.credentialIssuerIdentifier.url.absoluteString
        let header = DefaultJWSHeaderImpl(
          algorithm: try algorithm.parseToJoseLibrary(),
          jwk: jwk,
          type: "openid4vci-proof+jwt"
        )

        let jwt = try JWT.signed(
          claims: {
            IssuedAtClaim(value: Date())
            AudienceClaim(value: aud)
            StringClaim(key: "nonce", value: cNonce ?? "")
            IssuerClaim(value: issuer ?? "")
          },
          protectedHeader: header,
          key: privateKey
        )

        return .jwt(jwt.jwtString)
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
