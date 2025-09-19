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
    
    let contentType = getContentType(from: rawResponse.headers)
    let isJWTResponse = contentType?.contains("application/jwt") == true
    
    if isJWTResponse {
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
  
  func handleJWTMetadata(
    data: Data,
    policy: IssuerMetadataPolicy,
    issuerId: CredentialIssuerId
  ) async throws -> CredentialIssuerMetadata {
    
    guard let jwsString = String(data: data, encoding: .utf8) else {
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
  
  func getContentType(from headers: [String: String]) -> String? {
    for (key, value) in headers {
      if key.lowercased() == "content-type" {
        return value.lowercased()
      }
    }
    return nil
  }
  
  func getIssuerTrust(for policy: IssuerMetadataPolicy) -> IssuerTrust? {
    switch policy {
    case .requireSigned(let trust):
      return trust
    case .preferSigned(let trust):
      return trust
    case .ignoreSigned:
      return nil
    }
    
    func parseAndVerifySignedMetadata(
      _ metadata: String,
      issuerTrust: IssuerTrust,
      issuerId: CredentialIssuerId
    ) async throws -> CredentialIssuerMetadata {
      
      guard
        let jws = try? JWS(compactSerialization: metadata),
        let x5c = jws.header.x5c
      else {
        throw CredentialIssuerMetadataError.missingSignedMetadata
      }
      
      try await issuerTrust.verify(jws: jws, chain: x5c)
      
      let payloadData = jws.payload.data()
      return try JSONDecoder().decode(CredentialIssuerMetadata.self, from: payloadData)
    }
  }
  
  func parseAndVerifySignedMetadata(
    _ metadata: String,
    issuerTrust: IssuerTrust,
    issuerId: CredentialIssuerId
  ) async throws -> CredentialIssuerMetadata {
    
    guard
      let jws = try? JWS(compactSerialization: metadata),
      let x5c = jws.header.x5c
    else {
      throw CredentialIssuerMetadataError.missingSignedMetadata
    }
    
    try await issuerTrust.verify(jws: jws, chain: x5c)
    
    let payloadData = jws.payload.data()
    return try JSONDecoder().decode(CredentialIssuerMetadata.self, from: payloadData)
  }
  
}

private extension IssuerTrust {
  
  @discardableResult
  func verify(
    jws: JWS,
    chain: [String]
  ) async throws -> JWS {
    switch self {
    case .byPublicKey(let jwk):
      let algorithm: SignatureAlgorithm
      switch jwk.keyType {
      case .RSA:
        algorithm = .RS256
      case .EC:
        algorithm = .ES256
      default:
        throw CredentialIssuerMetadataError.invalidSignedMetadata(
          "Unsupported key type: \(jwk.keyType)"
        )
      }
      
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

