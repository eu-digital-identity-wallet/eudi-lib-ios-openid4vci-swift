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
import CryptoKit

public struct PKCEGenerator {

  // RFC 7636: code_verifier length MUST be between 43 and 128 characters
  private static let minCodeVerifierLength = 43
  private static let maxCodeVerifierLength = 128

  /// Default RFC7636-minimum-length code verifier (43 chars).
  public static func codeVerifier() -> String? {
    Self.codeVerifier(length: Self.minCodeVerifierLength)
  }

  /// RFC7636-conformant code verifier generator.
  /// - Parameter length: Must be in 43...128 (RFC7636).
  public static func codeVerifier(length: Int) -> String? {
    guard (minCodeVerifierLength...maxCodeVerifierLength).contains(length) else {
      return nil
    }
    return Self.generateRandomString(length: length)
  }

  public static func generateRandomData(length: Int = 48) -> Data? {
    var data = Data(count: length)
    let result = data.withUnsafeMutableBytes { mutableBytes in
      SecRandomCopyBytes(kSecRandomDefault, length, mutableBytes.baseAddress!)
    }
    
    guard result == errSecSuccess else {
      return nil // Random data generation failed
    }
    
    return data
  }
  
  /// RFC 7636 §4.1 unreserved characters: `[A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"`.
  static let unreservedCharacters: [Character] = Array(
    "abcdefghijklmnopqrstuvwxyz" +
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
    "0123456789" +
    "-._~"
  )

  /// Random string of `length` characters drawn uniformly from `unreservedCharacters`.
  ///
  /// Uses `randomElement()`, backed by `SystemRandomNumberGenerator` (cryptographically secure on
  /// Apple platforms), so every character is equally likely. Mapping random bytes with `% 66`
  /// would favour some characters.
  public static func generateRandomString(length: Int = 48) -> String? {
    guard length >= 0 else {
      return nil
    }
    return String((0..<length).compactMap { _ in unreservedCharacters.randomElement() })
  }

  public static func generateRandomBase64String(length: Int = 48) -> String? {
    guard let randomString = generateRandomString(length: length) else {
      return nil
    }
    return Data(randomString.utf8).base64EncodedString()
  }
  
  public static func generateCodeChallenge() -> String? {
    guard let randomVerifierString = generateRandomBase64String() else {
      return nil
    }
    
    if let data = randomVerifierString.data(using: .utf8) {
      let hashed = SHA256.hash(data: data)
      let challenge = Data(hashed).base64EncodedString()
      return challenge
    }
    return nil
  }
  
  public static func generateCodeChallenge(codeVerifier: String) -> String {
    guard let codeVerifierData = codeVerifier.data(using: .utf8) else {
      fatalError("Unable to convert code verifier to data.")
    }
    
    let hashedData = SHA256.hash(data: codeVerifierData)
    let base64Encoded = Data(hashedData).base64EncodedString()
    
    // URL safe encoding
    let codeChallenge = base64Encoded
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .trimmingCharacters(in: CharacterSet(charactersIn: "="))
    
    return codeChallenge
  }
}
