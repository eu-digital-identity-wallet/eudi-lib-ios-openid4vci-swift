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

public struct CredentialSupported: Codable {
  public let format: String?
  public let scope: String?
  public let cryptographicBindingMethodsSupported: [CryptographicBindingMethod]
  public let cryptographicSuitesSupported: [String]
  public let proofTypesSupported: [ProofType]?
  public let display: [Display]
  
  enum CodingKeys: String, CodingKey {
    case format
    case scope
    case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
    case cryptographicSuitesSupported = "cryptographic_suites_supported"
    case proofTypesSupported = "proof_types_supported"
    case display
  }
  
  public init(
    format: String?,
    scope: String?,
    cryptographicBindingMethodsSupported: [CryptographicBindingMethod],
    cryptographicSuitesSupported: [String],
    proofTypesSupported: [ProofType]?,
    display: [Display]
  ) {
    self.format = format
    self.scope = scope
    self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
    self.cryptographicSuitesSupported = cryptographicSuitesSupported
    self.proofTypesSupported = proofTypesSupported
    self.display = display
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    
    format = try container.decodeIfPresent(String.self, forKey: .format)
    scope = try container.decodeIfPresent(String.self, forKey: .scope)
    cryptographicBindingMethodsSupported = try container.decode([CryptographicBindingMethod].self, forKey: .cryptographicBindingMethodsSupported)
    cryptographicSuitesSupported = try container.decode([String].self, forKey: .cryptographicSuitesSupported)
    proofTypesSupported = try? container.decode([ProofType].self, forKey: .proofTypesSupported)
    display = try container.decode([Display].self, forKey: .display)
  }
  
  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    
    try container.encode(format, forKey: .format)
    try container.encode(scope, forKey: .scope)
    try container.encode(cryptographicBindingMethodsSupported, forKey: .cryptographicBindingMethodsSupported)
    try container.encode(cryptographicSuitesSupported, forKey: .cryptographicSuitesSupported)
    try container.encode(proofTypesSupported, forKey: .proofTypesSupported)
    try container.encode(display, forKey: .display)
  }
}
