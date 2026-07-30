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

    // Signature + chain verification is shared with the WRPRC path via JWSVerification.swift.
    // Translate the shared helper's errors back into CredentialIssuerMetadataError to preserve
    // existing metadata-error contracts.
    let verifiedJWS: JWS
    do {
      verifiedJWS = try await issuerTrust.verify(jws: jws)
    } catch let error as JWSVerificationError {
      switch error {
      case .chainNotTrusted:
        throw CredentialIssuerMetadataError.invalidSignedMetadata(
          "Failed to verify chain (.byCertificateChain)"
        )
      case .invalidCertificateChain(let reason),
           .verifierCreationFailed(let reason),
           .signatureInvalid(let reason),
           .unsupportedAlgorithm(let reason):
        throw CredentialIssuerMetadataError.invalidSignedMetadata(reason)
      }
    }

    // Metadata-specific: assert iss/sub/iat presence on the verified JWS
    _ = try verifiedJWS.validateSignedMetadataClaims()

    let payloadData = verifiedJWS.payload.data()
    let metadata = try JSONDecoder().decode(CredentialIssuerMetadata.self, from: payloadData)
    try validateJWTClaims(jws: verifiedJWS, expectedSubject: issuerId.url.absoluteString)

    // Capture the verified WRPAC (base64 DER — the LEAF of the JWS `x5c`
    // header) and attach it to the metadata so it can be used later by WRPRC
    // policy enforcement. The chain has already been trust-validated at this
    // point; only the leaf carries the WRP's identity.
    if let leaf = verifiedJWS.header.x5c?.first {
      return metadata.withWrpac(leaf)
    }
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
    let skew = SignedJWTValidation.clockSkew

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

