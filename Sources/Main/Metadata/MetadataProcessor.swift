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
@preconcurrency import JOSESwift

private enum SignedMetadataValidation {
  /// Default clock skew (seconds) used for validating `iat` and `exp`.
  /// Override by changing this value (library integrators can fork/configure).
  static let clockSkew: TimeInterval = 300
}

public protocol MetadataProcessing: Sendable {
  func processMetadata(
    rawResponse: RawFetchResponse,
    policy: IssuerMetadataPolicy,
    issuerId: CredentialIssuerId
  ) async throws -> CredentialIssuerMetadata
}

public struct MetadataProcessor: MetadataProcessing {
  public init() {}
  
  public func processMetadata(
    rawResponse: RawFetchResponse,
    policy: IssuerMetadataPolicy,
    issuerId: CredentialIssuerId
  ) async throws -> CredentialIssuerMetadata {
    
   let isJWT = try validateContentType(
      headers: rawResponse.headers,
      policy: policy
    )
    
    if isJWT {
      return try await handleJWTMetadata(
        data: rawResponse.data,
        policy: policy,
        issuerId: issuerId
      )
    } else {
      return try handleJSONMetadata(data: rawResponse.data)
    }
  }
}

private extension MetadataProcessor {
  
  func validateContentType(
    headers: [String: String],
    policy: IssuerMetadataPolicy
  ) throws -> Bool {
    
    guard let contentType = headers.first(where: { $0.key.lowercased() == "content-type" })?.value.lowercased() else {
      throw CredentialIssuerMetadataError.missingContentType("Credential issuer did not respond with a content type header")
    }
    
    let isJWT = contentType.contains(Constants.CONTENT_TYPE_APPLICATION_JWT)
    let isJSON = contentType.contains(Constants.CONTENT_TYPE_APPLICATION_JSON)
    
    // Validate content type based on policy and determine if JWT response
    switch policy {
    case .requireSigned:
      guard isJWT else {
        throw CredentialIssuerMetadataError.missingRightContentTypeHeader
      }
      return true
      
    case .preferSigned:
      guard isJWT || isJSON else {
        throw CredentialIssuerMetadataError.missingRightContentTypeHeader
      }
      return isJWT
      
    case .ignoreSigned:
      guard isJSON else {
        throw CredentialIssuerMetadataError.missingRightContentTypeHeader
      }
      return false
    }
  }
  
  func handleJWTMetadata(
    data: Data,
    policy: IssuerMetadataPolicy,
    issuerId: CredentialIssuerId
  ) async throws -> CredentialIssuerMetadata {
    
    guard let jwsString = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) else {
      throw CredentialIssuerMetadataError.nonParseableSignedMetadata
    }
    
    guard let issuerTrust = getIssuerTrust(for: policy) else {
      throw CredentialIssuerMetadataError.invalidIssuerTrust
    }
    
    return try await parseAndVerifySignedMetadata(
      jwsString,
      issuerTrust: issuerTrust,
      issuerId: issuerId
    )
  }
  
  func handleJSONMetadata(data: Data) throws -> CredentialIssuerMetadata {
    do {
      return try JSONDecoder().decode(CredentialIssuerMetadata.self, from: data)
    } catch {
      throw CredentialIssuerMetadataError.nonParseableCredentialIssuerMetadata(cause: error)
    }
  }
  
  
  func getIssuerTrust(for policy: IssuerMetadataPolicy) -> IssuerTrust? {
    switch policy {
    case .requireSigned(let trust), .preferSigned(let trust):
      return trust
    case .ignoreSigned:
      return nil
    }
  }
  
  func parseAndVerifySignedMetadata(
    _ metadata: String,
    issuerTrust: IssuerTrust,
    issuerId: CredentialIssuerId
  ) async throws -> CredentialIssuerMetadata {
    
    let jws = try JWS(compactSerialization: metadata)
    
    try validateJOSEHeader(jws.header)
    
    // Verify signature + claims in one centralized place
    let verifiedJWS = try await issuerTrust.verify(jws: jws)
    
    let payloadData = verifiedJWS.payload.data()
    let metadata = try JSONDecoder().decode(CredentialIssuerMetadata.self, from: payloadData)
    try validateJWTClaims(jws: verifiedJWS, expectedSubject: issuerId.url.absoluteString)
    return metadata
  }
  

  private func validateJOSEHeader(_ header: JWSHeader) throws {
    guard let
            headerType = header.typ,
          headerType == Constants.SIGNED_METADATA_JWT_TYPE
    else {
      throw CredentialIssuerMetadataError.invalidSignedMetadata(
        "Invalid 'typ' header. Expected: \(Constants.SIGNED_METADATA_JWT_TYPE)"
      )
    }
  }

  private func validateJWTClaims(jws: JWS, expectedSubject: String) throws {
    let data = jws.payload.data()
    guard
      let claims = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
      let sub = claims[JWTClaimNames.subject] as? String,
      let iat = claims[JWTClaimNames.issuedAt] as? TimeInterval
    else {
      throw CredentialIssuerMetadataError.invalidSignedMetadata("Missing required claims")
    }
    
    guard sub == expectedSubject else {
      throw CredentialIssuerMetadataError.invalidSignedMetadata("Invalid 'sub' claim. Expected: \(expectedSubject)")
    }
    
    let currentTime = Date().timeIntervalSince1970
    let skew = SignedMetadataValidation.clockSkew

    // iat must not be in the future beyond skew
    if iat > currentTime + skew {
      throw CredentialIssuerMetadataError.invalidSignedMetadata("JWT issued in the future")
    }

    // exp must not be expired beyond skew (consistent with iat skew handling)
    if let exp = claims[JWTClaimNames.expirationTime] as? TimeInterval {
      if exp < currentTime - skew {
        throw CredentialIssuerMetadataError.invalidSignedMetadata("JWT has expired")
      }

      // prevent strange case where iat is after exp
      if iat > exp + skew {
        throw CredentialIssuerMetadataError.invalidSignedMetadata("JWT 'iat' is after 'exp'")
      }
    }
  }
}

private extension IssuerTrust {
  
  @discardableResult
  func verify(
    jws: JWS
  ) async throws -> JWS {
    switch self {
    // NOTE: Only RS256 (RSA) and ES256 (EC P-256) are supported for signed metadata verification.
    case .byPublicKey(let jwk):
      let algorithm = try supportedSignatureAlgorithm(for: jwk)
      
      guard
        let key = try JWKSecKeyConverter(jwk: jwk).secKey(),
        let verifier: Verifier = .init(
          signatureAlgorithm: algorithm,
          key: key
        ) else {
        throw CredentialIssuerMetadataError.invalidSignedMetadata(
          "Failed to create verifier"
        )
      }
      return try jws.validate(using: verifier)
      
    case .byCertificateChain(let certificateChainTrust):
      let chain = jws.header.x5c ?? []
      guard certificateChainTrust.isValid(chain: chain) else {
        throw CredentialIssuerMetadataError.invalidSignedMetadata(
          "Failed to verify chain (.byCertificateChain)"
        )
      }
      
      let utilities: SecCertificateHelper = .init()
      guard
        let first = chain.first,
        let key = utilities.publicKey(fromPem: first),
        let algorithm: SignatureAlgorithm = switch key.keyAlgorithm() {
        case "RSA": .RS256
        case "EC": .ES256
        default: nil
        },
      let verifier: Verifier = .init(
        signatureAlgorithm: algorithm,
        key: key
      )
      else {
        throw CredentialIssuerMetadataError.invalidSignedMetadata(
          "Failed to create verifier (.byCertificateChain)"
        )
      }
      
      let verifiedJWS = try jws
        .validate(using: verifier)
        .validateSignedMetadataClaims()
      
      return verifiedJWS
    }
  }
}

private extension JWS {
  
  /// Validates the required claims: `iat`, `iss`, and `sub`
  /// - Returns: `self` if all claims are present and valid, throws otherwise.
  func validateSignedMetadataClaims() throws -> JWS {
    
    let data = self.payload.data()
    /// Decode Payload (Assuming it's a JSON object)
    guard
      let json = try JSONSerialization.jsonObject(
        with: data,
        options: []
      ) as? [String: Any]
    else {
      throw CredentialIssuerMetadataError.invalidSignedMetadata(
        "Unable to decode JWS"
      )
    }
    
    /// Validate required claims
    guard
      let _ = json[JWTClaimNames.issuedAt] as? TimeInterval,
      let _ = json[JWTClaimNames.issuer] as? String,
      let _ = json[JWTClaimNames.subject] as? String
    else {
      throw CredentialIssuerMetadataError.invalidSignedMetadata(
        "Expected claims not found in signed metadata"
      )
    }
    return self
  }
}

private extension IssuerTrust {
  func supportedSignatureAlgorithm(for jwk: JWK) throws -> SignatureAlgorithm {
    // If the JWK declares an alg, enforce it.
    if let alg = jwk.parameters["alg"]?.uppercased() {
      switch alg {
      case "RS256": return .RS256
      case "ES256": return .ES256
      default:
        throw CredentialIssuerMetadataError.invalidSignedMetadata(
          "Unsupported JWK alg '\(alg)'. Only RS256 and ES256 are supported."
        )
      }
    }

    // If no alg is declared, fall back to key type, but still only allow RS256/ES256.
    switch jwk.keyType {
    case .RSA: return .RS256
    case .EC:  return .ES256
    default:
      throw CredentialIssuerMetadataError.invalidSignedMetadata(
        "Unsupported key type: \(jwk.keyType). Only RSA (RS256) and EC P-256 (ES256) are supported."
      )
    }
  }
}
