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

/*
This enum represents a set of JOSE (Javascript Object Signing and Encryption) errors.
It conforms to the LocalizedError protocol so we can get a human-readable error description.
*/
public enum JOSEError: LocalizedError {
  // The error case representing an unsupported request
  case notSupportedRequest
  case invalidIdTokenRequest
  case invalidPublicKey
  case invalidJWS
  case invalidSigner
  case invalidVerifier
  case invalidDidIdentifier
  case invalidObjectType

  // A computed property to provide a description for each error case
  public var errorDescription: String? {
    switch self {
    case .notSupportedRequest:
      return ".notSupportedRequest"
    case .invalidIdTokenRequest:
      return ".invalidIdTokenRequest"
    case .invalidPublicKey:
      return ".invalidPublicKey"
    case .invalidJWS:
      return ".invalidJWS"
    case .invalidSigner:
      return ".invalidSigner"
    case .invalidVerifier:
      return ".invalidVerifier"
    case .invalidDidIdentifier:
      return ".invalidDidIdentifier"
    case .invalidObjectType:
      return ".invalidObjectType"
    }
  }
}

extension JOSESwiftError: LocalizedError {
  
  public var errorDescription: String? {
    switch self {
    case .signingFailed(let description):
      return ".signingFailed: \(description)"
    case .verifyingFailed(let description):
      return ".verifyingFailed: \(description)"
    case .signatureInvalid:
      return ".signatureInvalid"
    case .encryptingFailed(let description):
      return ".encryptingFailed: \(description)"
    case .decryptingFailed:
      return ".decryptingFailed"
    case .wrongDataEncoding:
      return ".wrongDataEncoding"
    case .invalidCompactSerializationComponentCount(let count):
      return ".invalidCompactSerializationComponentCount: \(count)"
    case .componentNotValidBase64URL(let component):
      return ".componentNotValidBase64URL: \(component)"
    case .componentCouldNotBeInitializedFromData:
      return ".componentCouldNotBeInitializedFromData"
    case .couldNotConstructJWK:
      return ".couldNotConstructJWK"
    case .modulusNotBase64URLUIntEncoded:
      return ".modulusNotBase64URLUIntEncoded"
    case .exponentNotBase64URLUIntEncoded:
      return ".exponentNotBase64URLUIntEncoded"
    case .privateExponentNotBase64URLUIntEncoded:
      return ""
    case .symmetricKeyNotBase64URLEncoded:
      return ".symmetricKeyNotBase64URLEncoded"
    case .xNotBase64URLUIntEncoded:
      return ".xNotBase64URLUIntEncoded"
    case .yNotBase64URLUIntEncoded:
      return ".yNotBase64URLUIntEncoded"
    case .privateKeyNotBase64URLUIntEncoded:
      return ".privateKeyNotBase64URLUIntEncoded"
    case .invalidCurveType:
      return ".invalidCurveType"
    case .compressedCurvePointsUnsupported:
      return ".compressedCurvePointsUnsupported"
    case .invalidCurvePointOctetLength:
      return ".invalidCurvePointOctetLength"
    case .localAuthenticationFailed(let errorCode):
      return ".localAuthenticationFailed: \(errorCode)"
    case .compressionFailed:
      return ".compressionFailed"
    case .decompressionFailed:
      return ".decompressionFailed"
    case .compressionAlgorithmNotSupported:
      return ".compressionAlgorithmNotSupported"
    case .rawDataMustBeGreaterThanZero:
      return ".rawDataMustBeGreaterThanZero"
    case .compressedDataMustBeGreaterThanZero:
      return ".compressedDataMustBeGreaterThanZero"
    case .thumbprintSerialization:
      return ".thumbprintSerialization"
    }
  }
}
