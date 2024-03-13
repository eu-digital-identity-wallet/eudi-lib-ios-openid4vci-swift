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
import SwiftyJSON

public struct W3CVerifiableCredentialsJsonLdDataIntegrityCredentialSupported: Codable {
  public let format: String
  public let scope: String?
  public let cryptographicBindingMethodsSupported: [String]?
  public let credentialSigningAlgValuesSupported: [String]?
  public let proofTypesSupported: [String]?
  public let display: [Display]?
  public let context: [String]
  public let type: [String]
  public let credentialDefinition: JSON
  public let order: [String]?
  
  enum CodingKeys: String, CodingKey {
    case format
    case scope
    case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
    case credentialSigningAlgValuesSupported = "credential_signing_alg_values_supported"
    case proofTypesSupported = "proof_types_supported"
    case display
    case context = "@context"
    case type
    case credentialDefinition = "credential_definition"
    case order
  }
  
  public init(
    format: String,
    scope: String? = nil,
    cryptographicBindingMethodsSupported: [String]? = nil,
    credentialSigningAlgValuesSupported: [String]? = nil,
    proofTypesSupported: [String]? = nil,
    display: [Display]? = nil,
    context: [String] = [],
    type: [String] = [],
    credentialDefinition: JSON,
    order: [String]? = nil
  ) {
    self.format = format
    self.scope = scope
    self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
    self.credentialSigningAlgValuesSupported = credentialSigningAlgValuesSupported
    self.proofTypesSupported = proofTypesSupported
    self.display = display
    self.context = context
    self.type = type
    self.credentialDefinition = credentialDefinition
    self.order = order
  }
}
