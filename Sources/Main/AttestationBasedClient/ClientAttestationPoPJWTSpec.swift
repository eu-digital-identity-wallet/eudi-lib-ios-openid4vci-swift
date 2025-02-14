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

enum ClientAttestationPoPJWTSpecError: Error, LocalizedError {
  case invalidAlgorithm
  case nonPositiveDuration
  
  var errorDescription: String? {
    switch self {
    case .invalidAlgorithm:
      return "Signing algorithm cannot be a MAC algorithm."
    case .nonPositiveDuration:
      return "JWT duration must be positive."
    }
  }
}

public struct ClientAttestationPoPJWTSpec {
  // MARK: - Properties
  
  public let signingAlgorithm: SignatureAlgorithm
  public let duration: TimeInterval
  public let typ: String
  public let jwsSigner: Signer
  
  // MARK: - Initializer
  
  public init(
    signingAlgorithm: SignatureAlgorithm,
    duration: TimeInterval = 300, // Default to 5 minutes
    typ: String,
    jwsSigner: Signer
  ) throws {
    // Validate the signing algorithm (must not be MAC)
    try Self.requireIsNotMAC(signingAlgorithm)
    
    // Validate that the duration is positive
    guard duration > 0 else {
      throw ClientAttestationPoPJWTSpecError.nonPositiveDuration
    }
    
    self.signingAlgorithm = signingAlgorithm
    self.duration = duration
    self.typ = typ
    self.jwsSigner = jwsSigner
  }
  
  // MARK: - Helper Functions
  
  /// Ensure that the algorithm is not a MAC algorithm
  private static func requireIsNotMAC(_ algorithm: SignatureAlgorithm) throws {
    let macAlgorithms: [SignatureAlgorithm] = [.HS256, .HS384, .HS512] // HMAC algorithms
    if macAlgorithms.contains(algorithm) {
      throw ClientAttestationPoPJWTSpecError.invalidAlgorithm
    }
  }
}




