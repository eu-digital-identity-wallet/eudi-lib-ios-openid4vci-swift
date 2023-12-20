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
  
  public static func codeVerifier() -> String? {
    Self.generateRandomString(length: 43)
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
  
  public static func generateRandomString(length: Int = 48) -> String? {
    // Define your character sets
    let lowercaseCharacters = "abcdefghijklmnopqrstuvwxyz"
    let uppercaseCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    let numberCharacters = "0123456789"
    let specialCharacters = "-._~"
    
    // Combine all character sets
    let allCharacters = lowercaseCharacters + uppercaseCharacters + numberCharacters + specialCharacters
    
    // Generate random bytes
    guard let randomBytes = generateRandomData(length: length) else {
      return nil
    }
    
    // Convert random bytes to characters based on the combined character set
    var randomString = ""
    for byte in randomBytes {
      let randomIndex = Int(byte) % allCharacters.count
      let randomCharacter = allCharacters[allCharacters.index(allCharacters.startIndex, offsetBy: randomIndex)]
      randomString.append(randomCharacter)
    }
    
    return randomString
  }
  
  public static func generateRandomBase64String(length: Int = 48) -> String? {
    // Define your character sets
    let lowercaseCharacters = "abcdefghijklmnopqrstuvwxyz"
    let uppercaseCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    let numberCharacters = "0123456789"
    let specialCharacters = "-._~"
    
    // Combine all character sets
    let allCharacters = lowercaseCharacters + uppercaseCharacters + numberCharacters + specialCharacters
    
    // Generate random bytes
    guard let randomBytes = generateRandomData(length: length) else {
      return nil
    }
    
    // Convert random bytes to characters based on the combined character set
    var randomString = ""
    for byte in randomBytes {
      let randomIndex = Int(byte) % allCharacters.count
      let randomCharacter = allCharacters[allCharacters.index(allCharacters.startIndex, offsetBy: randomIndex)]
      randomString.append(randomCharacter)
    }
    
    // Encode the random string as Base64
    if let data = randomString.data(using: .utf8) {
      return data.base64EncodedString()
    }
    
    return nil
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
