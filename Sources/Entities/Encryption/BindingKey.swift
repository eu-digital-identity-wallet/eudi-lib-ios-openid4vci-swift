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
  
  case jwt(
    algorithm: JWSAlgorithm,
    jwk: JWK,
    privateKey: SigningKeyProxy,
    issuer: String? = nil
  )
  
  case attestation(
    keyAttestationJWT: @Sendable (_ nonce: String?) async throws -> KeyAttestationJWT
  )
  
  case jwtKeyAttestation(
    algorithm: JWSAlgorithm,
    keyAttestationJWT: @Sendable (_ nonce: String?) async throws -> KeyAttestationJWT,
    keyIndex: UInt,
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
    case (.jwt, .jwt),
      (.did, .did),
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
    omitIss: Bool,
  ) async throws -> Proof {
    switch self {
    case .jwt(
      let algorithm,
      let jwk,
      let privateKey,
      let issuer
    ):
      let proofTypesSupported = credentialSpec.proofTypesSupported
      let suites = proofTypesSupported?["jwt"]?.algorithms.contains { $0 == algorithm.name } ??  true
      guard suites else {
        throw CredentialIssuanceError.cryptographicSuiteNotSupported(algorithm.name)
      }
      
      let keyAttestationRequirement = proofTypesSupported?["jwt"]?.keyAttestationRequirement
      switch keyAttestationRequirement {
      case .required, .requiredNoConstraints:
        throw CredentialIssuanceError.proofTypeKeyAttestationRequired
      default: break
      }
      
      let proofs = proofTypesSupported?.keys.contains { $0 == "jwt" } ?? true
      guard proofs else {
        throw CredentialIssuanceError.proofTypeNotSupported
      }
      
      let aud = issuanceRequester.issuerMetadata.credentialIssuerIdentifier.url.absoluteString
      
      let header: JWSHeader = try .init(parameters: [
        JWTClaimNames.type: Self.OpenID4VCIProofJWT,
        JWTClaimNames.algorithm: algorithm.name,
        JWTClaimNames.JWK: jwk.toDictionary()
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
        
        if key == JWTClaimNames.issuer, omitIss {
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
      
      let header: JWSHeader = try .init(
        parameters: [
          JWTClaimNames.algorithm: algorithm.name,
          JWTClaimNames.kid: "\(keyIndex)",
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
