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
import Security
import JOSESwift

/// A struct that converts a JOSESwift JWK into a SecKey.
struct JWKSecKeyConverter {
  let jwk: JWK
  
  /// Returns a SecKey built from the JWK.
  func secKey() throws -> SecKey? {
    let keyType = jwk.keyType.rawValue
    
    switch keyType {
    case "EC":
      return try secKeyFromECJWK(jwk: jwk)
    case "RSA":
      return try secKeyFromRSAJWK(jwk: jwk)
    default:
      return nil
    }
  }
  
  // MARK: - EC Key Conversion
  
  private func secKeyFromECJWK(jwk: JWK) throws -> SecKey? {
    
    guard
      let xBase64 = jwk["x"],
      let yBase64 = jwk["y"],
      let crv = jwk["crv"]
    else {
      return nil
    }
    
    // Decode the Base64URL-encoded x and y values.
    guard
      let xData = Data(base64URLEncoded: xBase64),
      let yData = Data(base64URLEncoded: yBase64)
    else {
      return nil
    }
    
    // Determine the expected key length based on the curve.
    let ecKeySize: Int
    switch crv {
    case "P-256": ecKeySize = 32
    case "P-384": ecKeySize = 48
    case "P-521": ecKeySize = 66
    default:
      return nil
    }
    
    // Ensure the decoded values have the correct length.
    guard
      xData.count == ecKeySize,
      yData.count == ecKeySize
    else {
      return nil
    }
    
    // Create the uncompressed public key data (0x04 | x | y).
    let asn1Header: [UInt8] = [0x04]
    let publicKeyData = Data(asn1Header) + xData + yData
    
    // Attributes for the SecKey creation.
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
      kSecAttrKeySizeInBits as String: ecKeySize * 8
    ]
    
    guard let secKey = SecKeyCreateWithData(publicKeyData as CFData, attributes as CFDictionary, nil) else {
      return nil
    }
    
    return secKey
  }
  
  // MARK: - RSA Key Conversion
  
  private func secKeyFromRSAJWK(jwk: JWK) throws -> SecKey? {
    
    // Ensure the JWK has all required RSA parameters.
    guard
      let nBase64 = jwk["n"],
        let eBase64 = jwk["e"]
    else {
      return nil
    }
    
    // Decode the Base64URL-encoded modulus and exponent.
    guard
      let nData = Data(base64URLEncoded: nBase64),
      let eData = Data(base64URLEncoded: eBase64)
    else {
      return nil
    }
    
    // Build the ASN.1 representation of the RSA public key.
    let rsaKeyData = try encodeRSAPublicKey(modulus: nData, exponent: eData)
    
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
      kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
      kSecAttrKeySizeInBits as String: nData.count * 8
    ]
    
    guard let secKey = SecKeyCreateWithData(rsaKeyData as CFData, attributes as CFDictionary, nil) else {
      return nil
    }
    
    return secKey
  }
  
  // MARK: - RSA ASN.1 Encoding Helpers
  
  private func encodeRSAPublicKey(modulus: Data, exponent: Data) throws -> Data {
    let modulusBytes = modulus.bytes
    let exponentBytes = exponent.bytes
    
    // Add a leading zero if needed (if the most significant bit is set).
    let modulusWithLeadingZero = modulusBytes.first! >= 0x80 ? [0x00] + modulusBytes : modulusBytes
    let exponentWithLeadingZero = exponentBytes.first! >= 0x80 ? [0x00] + exponentBytes : exponentBytes
    
    let modulusLength = encodeASN1Length(modulusWithLeadingZero.count)
    let exponentLength = encodeASN1Length(exponentWithLeadingZero.count)
    
    let totalLength = 1 + modulusLength.count + modulusWithLeadingZero.count +
    1 + exponentLength.count + exponentWithLeadingZero.count
    let sequenceLength = encodeASN1Length(totalLength)
    
    let sequence: [UInt8] = [0x30] + sequenceLength
    let modulusField: [UInt8] = [0x02] + modulusLength + modulusWithLeadingZero
    let exponentField: [UInt8] = [0x02] + exponentLength + exponentWithLeadingZero
    
    return Data(sequence + modulusField + exponentField)
  }
  
  private func encodeASN1Length(_ length: Int) -> [UInt8] {
    if length < 0x80 {
      return [UInt8(length)]
    } else {
      let lengthBytes = withUnsafeBytes(of: length.bigEndian, Array.init).drop { $0 == 0 }
      return [0x80 | UInt8(lengthBytes.count)] + lengthBytes
    }
  }
}

// MARK: - Data Extensions

extension Data {
  /// Returns the array of bytes.
  var bytes: [UInt8] {
    return [UInt8](self)
  }
}
