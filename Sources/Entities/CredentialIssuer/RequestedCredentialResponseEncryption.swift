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

public enum RequestedCredentialResponseEncryption {
  
  // No encryption is requested
  case notRequested
  
  // The encryption parameters that are sent along with the issuance request.
  // - Parameters:
  //   - encryptionJwk: Key pair in JWK format used for issuance response encryption/decryption
  //   - responseEncryptionAlg: Encryption algorithm to be used
  //   - responseEncryptionMethod: Encryption method to be used
  case requested(
    encryptionJwk: JWK,
    encryptionKey: SecKey,
    responseEncryptionAlg: JWEAlgorithm,
    responseEncryptionMethod: JOSEEncryptionMethod
  )
  
  // Validate algorithm provided is for asymmetric encryption
  private static func validateAlgorithm(_ responseEncryptionAlg: JWEAlgorithm?) throws {
    guard
      let responseEncryptionAlg = responseEncryptionAlg,
      JWEAlgorithm.Family.parse(.ASYMMETRIC).contains(responseEncryptionAlg)
    else {
      throw ValidationError.error(reason: "Provided encryption algorithm is not an asymmetric encryption algorithm")
    }
  }
  
  // Validate algorithm matches key
  private static func validateKeyAlgorithmMatch(_ encryptionJwk: JWK?, _ responseEncryptionAlg: JWEAlgorithm?) throws {
    /*guard encryptionJwk.keyType == KeyType.forAlgorithm(responseEncryptionAlg) else {
      throw ValidationError.error(reason: "Encryption key and encryption algorithm do not match")
    }*/
  }
  
  // Validate key is for encryption operation
  private static func validateKeyUse(_ encryptionJwk: JWK?) throws {
    guard encryptionJwk?.parameters["use"] == "enc" else {
      throw ValidationError.error(reason: "Provided key use is not encryption")
    }
  }
  
  // Validate the requested encryption parameters
  private static func validate(
    encryptionJwk: JWK?,
    responseEncryptionAlg: JWEAlgorithm?,
    responseEncryptionMethod: JOSEEncryptionMethod?
  ) throws {
    try validateAlgorithm(responseEncryptionAlg)
    try validateKeyAlgorithmMatch(encryptionJwk, responseEncryptionAlg)
    try validateKeyUse(encryptionJwk)
  }
  
  // Initialization from the requested encryption parameters
  public init(
    encryptionJwk: JWK?,
    encryptionKey: SecKey?,
    responseEncryptionAlg: JWEAlgorithm?,
    responseEncryptionMethod: JOSEEncryptionMethod?
  ) throws {
    
    guard
      let encryptionJwk,
      let encryptionKey,
      let responseEncryptionAlg,
      let responseEncryptionMethod
    else {
      self = .notRequested
      return
    }
    
    try Self.validate(
      encryptionJwk: encryptionJwk,
      responseEncryptionAlg: responseEncryptionAlg,
      responseEncryptionMethod: responseEncryptionMethod
    )
    
    self = .requested(
      encryptionJwk: encryptionJwk,
      encryptionKey: encryptionKey,
      responseEncryptionAlg: responseEncryptionAlg,
      responseEncryptionMethod: responseEncryptionMethod
    )
  }
}
