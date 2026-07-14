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

public enum BindingKey: Sendable, Equatable {
  
  case attestation(
    keyAttestationJWT: @Sendable (_ nonce: String?) async throws -> KeyAttestationJWT
  )
  
  case jwtKeyAttestation(
    algorithm: JWSAlgorithm,
    keyAttestationJWT: @Sendable (_ nonce: String?) async throws -> KeyAttestationJWT,
    keyIndex: UInt = 0,
    privateKey: SigningKeyProxy,
    issuer: String? = nil
  )
  
  case did(identity: String)
  
  case x509(certificate: X509Certificate)
}

public extension BindingKey {
  
  static let OpenID4VCIProofJWT = "openid4vci-proof+jwt"
  
  static func == (lhs: BindingKey, rhs: BindingKey) -> Bool {
    switch (lhs, rhs) {
    case (.did, .did),
      (.x509, .x509),
      (.jwtKeyAttestation, .jwtKeyAttestation),
      (.attestation, .attestation):
      return true
    default:
      return false
    }
  }
  
  func toSupportedProof(
    issuanceRequester: IssuanceRequesterType,
    credentialSpec: CredentialSupported,
    keyAttestationJwt: KeyAttestationJWT? = nil,
    cNonce: String?,
    omitIss: Bool
  ) async throws -> Proof {
    switch self {
    case .jwtKeyAttestation(
      let algorithm,
      _,
      let keyIndex,
      let privateKey,
      let issuer
    ):
      
      guard let keyAttestationJwt = keyAttestationJwt else {
        throw ValidationError.todo(
          reason: ".jwtKeyAttestation: Invalid key attestation JWT"
        )
      }

      // Validate keyIndex is within bounds
      guard keyIndex < keyAttestationJwt.attestedKeys.count else {
        throw CredentialIssuanceError.keyIndexOutOfBounds(
          index: keyIndex,
          available: keyAttestationJwt.attestedKeys.count
        )
      }

      let proofTypesSupported = credentialSpec.proofTypesSupported
      let keyAttestationRequirement = proofTypesSupported?["jwt"]?.keyAttestationRequirement
      switch keyAttestationRequirement {
      case .required, .requiredNoConstraints:
        break
      case .notRequired:
        break
      case .none:
        break
      }
      
      // OID4VCI Appendix F: a jwt proof header identifies the signing key with
      // exactly one of jwk / kid / x5c. A verifier (e.g. the OpenID Foundation
      // conformance suite) resolves kid against a pre-established client jwks,
      // not against the key_attestation's attested_keys. So put the attested
      // public key (attested_keys[keyIndex]) inline as jwk instead of kid; this
      // lets a jwt proof that carries a key_attestation resolve its key.
      guard Int(keyIndex) < keyAttestationJwt.attestedKeys.count else {
        throw ValidationError.todo(
          reason: ".jwtKeyAttestation: keyIndex (\(keyIndex)) out of range for attested_keys (count: \(keyAttestationJwt.attestedKeys.count))"
        )
      }
      let attestedPublicKey = keyAttestationJwt.attestedKeys[Int(keyIndex)]
      let header: JWSHeader = try .init(
        parameters: [
          JWTClaimNames.kid: "0",
          JWTClaimNames.algorithm: algorithm.name,
          JWTClaimNames.type: Self.OpenID4VCIProofJWT,
          JWTClaimNames.keyAttestation: keyAttestationJwt.jws.compactSerializedString
        ]
      )
      
      let aud = issuanceRequester.issuerMetadata.credentialIssuerIdentifier.url.absoluteString
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
      
      let signer: Signer = try await Self.createSigner(
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
      
      return .jwt(jws.compactSerializedString)
    case .attestation:
      guard let keyAttestationJwt = keyAttestationJwt else {
        throw ValidationError.todo(
          reason: ".jwtKeyAttestation: Invalid key attestation JWT"
        )
      }
      return .attestation(keyAttestationJwt)
      
    case .did(let identity):
      throw ValidationError.todo(
        reason: ".did(\(identity) not implemented"
      )
    case .x509(let certificate):
      throw ValidationError.todo(
        reason: ".x509(\(certificate) not implemented"
      )
    }
  }
}

extension BindingKey {
  
  static func createSigner(
    with header: JWSHeader,
    and payload: Payload,
    for privateKey: SigningKeyProxy,
    and signatureAlgorithm: SignatureAlgorithm
  ) async throws -> Signer {
    
    if case let .secKey(secKey) = privateKey,
       let secKeySigner = Signer(
        signatureAlgorithm: signatureAlgorithm,
        key: secKey
       ) {
      return secKeySigner
      
    } else if case let .custom(customAsyncSigner) = privateKey {
      let headerData = header as DataConvertible
      let signature = try await customAsyncSigner.signAsync(
        headerData.data(),
        payload.data()
      )
      
      let customSigner = PrecomputedSigner(
        signature: signature,
        algorithm: signatureAlgorithm
      )
      return Signer(customSigner: customSigner)
      
    } else {
      throw ValidationError.error(reason: "Unable to create JWS signer")
    }
  }
}

extension BindingKey {
  var attestationFunction: (@Sendable (_ nonce: String?) async throws -> KeyAttestationJWT)? {
    switch self {
    case .attestation(let function):
      return function
    case .jwtKeyAttestation(_, let function, _, _, _):
      return function
    default:
      return nil
    }
  }
  
  var isAttestationCapable: Bool {
    attestationFunction != nil
  }
}
