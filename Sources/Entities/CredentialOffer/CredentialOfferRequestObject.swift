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

public struct CredentialOfferRequestObject: Codable, Equatable {
  public let credentialIssuer: String
  public let credentials: JSON
  public let grants: GrantsObject?
  
  enum CodingKeys: String, CodingKey {
    case credentialIssuer = "credential_issuer"
    case credentials = "credentials"
    case grants = "grants"
  }
  
  public init(
    credentialIssuer: String,
    credentials: JSON,
    grants: GrantsObject?
  ) {
    self.credentialIssuer = credentialIssuer
    self.credentials = credentials
    self.grants = grants
  }
  
  public init?(jsonString: String) {
    guard let jsonData = jsonString.data(using: .utf8) else {
      return nil // Return nil if JSON string is invalid
    }
    
    do {
      let decoder = JSONDecoder()
      self = try decoder.decode(Self.self, from: jsonData)
    } catch {
      return nil
    }
  }
}

public extension CredentialOfferRequestObject {
  
  func toDomain() -> CredentialOffer? {
    nil
  }
}
