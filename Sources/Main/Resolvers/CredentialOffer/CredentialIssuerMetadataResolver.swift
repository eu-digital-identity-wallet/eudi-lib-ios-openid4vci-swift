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

public enum CredentialIssuerSource: Sendable {
  case credentialIssuer(CredentialIssuerId)
}

public protocol CredentialIssuerMetadataType {
  /// The input type for resolving a type.
  associatedtype InputType: Sendable
  
  /// The output type for resolved type. Must be Codable and Equatable.
  associatedtype OutputType: Decodable, Equatable, Sendable
  
  /// The error type for resolving type. Must conform to the Error protocol.
  associatedtype ErrorType: Error
  
  /// Resolves type asynchronously.
  ///
  /// - Parameters:
  ///   - source: The input source for resolving data.
  /// - Returns: An asynchronous result containing the resolved data or an error.
  func resolve(
    source: InputType,
    policy: IssuerMetadataPolicy
  ) async throws -> Result<OutputType, ErrorType>
}

public actor CredentialIssuerMetadataResolver: CredentialIssuerMetadataType {
  
  private let fetcher: Fetcher<CredentialIssuerMetadata>
  
  public init(
    fetcher: Fetcher<CredentialIssuerMetadata> = Fetcher()
  ) {
    self.fetcher = fetcher
  }
  
  /// Resolves client metadata asynchronously.
  ///
  /// - Parameters:
  ///   - source: The input source for resolving metadata.
  ///   - policy: The issuer metadata policy
  /// - Returns: An asynchronous result containing the resolved metadata or an error of type ResolvingError.
  public func resolve(
    source: CredentialIssuerSource,
    policy: IssuerMetadataPolicy
  ) async throws -> Result<CredentialIssuerMetadata, some Error> {
    switch source {
    case .credentialIssuer(let issuerId):
      let url = issuerId.url
        .appendingPathComponent(".well-known")
        .appendingPathComponent("openid-credential-issuer")
      let result = await fetcher.fetch(url: url)
      
      switch result {
      case .success(let metadata):
        switch policy {
        case .requireSigned(let issuerTrust):
          try await parseAndVerifySignedMetadata(
            metadata.signedMetadata,
            issuerTrust: issuerTrust,
            issuerId: issuerId
          )
          return result
          
        case .preferSigned(let issuerTrust):
          try? await parseAndVerifySignedMetadata(
            metadata.signedMetadata,
            issuerTrust: issuerTrust,
            issuerId: issuerId
          )
          return result
        case .ignoreSigned: return result
        }
      case .failure(let error):
        return .failure(error)
      }
    }
  }
}

private extension CredentialIssuerMetadataResolver {
  func parseAndVerifySignedMetadata(
    _ metadata: String?,
    issuerTrust: IssuerTrust,
    issuerId: CredentialIssuerId
  ) async throws {
    guard
      let metadata,
      let jws = try? JWS(compactSerialization: metadata),
      let x5c = jws.header.x5c
    else {
      throw CredentialIssuerMetadataError.missingSignedMetadata
    }
    
    try await issuerTrust.verify(
      jws: jws,
      chain: x5c
    )
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
      
      let verifiedJWS = try jws.validate(using: verifier)
      return verifiedJWS
    }
  }
}
