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

let OPENID_CREDENTIAL = "openid_credential"

public struct AuthorizationDetailJson: Codable {
  public let type: String
  public let format: String?
  public let credentialConfigurationId: String
  public let credentialIdentifiers: [String]
  
  // Custom initialization to enforce constraints
  public init(type: String, format: String? = nil, credentialConfigurationId: String, credentialIdentifiers: [String] = []) throws {
    guard type == OPENID_CREDENTIAL else {
      throw ValidationError.error(reason: "Invalid type")
    }
    
    self.type = type
    self.format = format
    self.credentialConfigurationId = credentialConfigurationId
    self.credentialIdentifiers = credentialIdentifiers
  }
}
