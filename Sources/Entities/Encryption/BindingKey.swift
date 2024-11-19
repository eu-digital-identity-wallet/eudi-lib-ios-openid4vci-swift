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
    privateKey: PrivateKeyProxy,
    issuer: String? = nil
  )

  // DID Binding Key
  case did(identity: String)

  // X509 Binding Key
  case x509(certificate: X509Certificate)

  public enum PrivateKeyProxy {
    case custom(any AsyncSignerProtocol)
    case secKey(SecKey)
  }
}

public extension BindingKey {

  func toSupportedProof(
    issuanceRequester: IssuanceRequesterType,
    credentialSpec: CredentialSupported,
    cNonce: String?
  ) async throws -> Proof {
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

        let header = try JWSHeader(parameters: [
          "typ": "openid4vci-proof+jwt",
          "alg": algorithm.name,
          "jwk": jwk.toDictionary()
        ])

        let dictionary: [String: Any] = [
          JWTClaimNames.issuedAt: Int(Date().timeIntervalSince1970.rounded()),
          JWTClaimNames.audience: aud,
          JWTClaimNames.nonce: cNonce ?? "",
          JWTClaimNames.issuer: issuer ?? ""
        ].filter { key, value in
          if let string = value as? String, string.isEmpty {
            return false
          }
          return true
        }

        let payload = Payload(try dictionary.toThrowingJSONData())

        guard let signatureAlgorithm = SignatureAlgorithm(rawValue: algorithm.name) else {
          throw CredentialIssuanceError.cryptographicAlgorithmNotSupported
        }
        let signer: Signer
        if case let .secKey(secKey) = privateKey, let secKeySigner = Signer(signatureAlgorithm: signatureAlgorithm, key: secKey) {
          signer = secKeySigner
        } else if case let .custom(customAsyncSigner) = privateKey {
					let signingInput = [header as DataConvertible, payload as DataConvertible].map { $0.data().base64URLEncodedString() }.joined(separator: ".").data(using: .ascii)!
					let signature = try await customAsyncSigner.signAsync(signingInput)
					let customSigner = PrecomputedSigner(signature: signature, algorithm: signatureAlgorithm)
          signer = Signer(customSigner: customSigner)
        } else {
          throw ValidationError.error(reason: "Unable to create JWS signer")
        }

        let jws = try JWS(
          header: header,
          payload: payload,
          signer: signer
        )

        return .jwt(jws.compactSerializedString)

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

        let header = try JWSHeader(parameters: [
          "typ": "openid4vci-proof+jwt",
          "alg": algorithm.name,
          "jwk": jwk.toDictionary()
        ])

        let dictionary: [String: Any] = [
          JWTClaimNames.issuedAt: Int(Date().timeIntervalSince1970.rounded()),
          JWTClaimNames.audience: aud,
          JWTClaimNames.nonce: cNonce ?? "",
          JWTClaimNames.issuer: issuer ?? ""
        ].filter { key, value in
          if let string = value as? String, string.isEmpty {
            return false
          }
          return true
        }

        let payload = Payload(try dictionary.toThrowingJSONData())

        guard let signatureAlgorithm = SignatureAlgorithm(rawValue: algorithm.name) else {
          throw CredentialIssuanceError.cryptographicAlgorithmNotSupported
        }

        guard let signer = Signer(
          signatureAlgorithm: signatureAlgorithm,
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

// we need this because secure are signer is async
class PrecomputedSigner: JOSESwift.SignerProtocol {
	var algorithm: JOSESwift.SignatureAlgorithm
	let signature: Data
	
	init(signature: Data, algorithm: JOSESwift.SignatureAlgorithm) {
		self.algorithm = algorithm
		self.signature = signature
	}
	
	func sign(_ signingInput: Data) throws -> Data {
		return signature
	}
}

public protocol AsyncSignerProtocol {
	func signAsync(_ signingInput: Data) async throws -> Data
}
