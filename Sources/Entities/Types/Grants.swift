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

public enum Grants {
  case authorizationCode(AuthorizationCode)
  case preAuthorizedCode(PreAuthorizedCode)
  case both(AuthorizationCode, PreAuthorizedCode)
  
  public struct AuthorizationCode {
    public let issuerState: String?
    public let authorizationServer: URL?
    
    public init(
      issuerState: String? = nil,
      authorizationServer: URL?
    ) throws {
      self.issuerState = issuerState
      self.authorizationServer = authorizationServer
      
      if let issuerState, issuerState.isEmpty {
        throw ValidationError.error(reason: "issuerState cannot be blank")
      }
    }
  }

  public struct PreAuthorizedCode {
    public let preAuthorizedCode: String?
    public let txCode: TxCode?
    
    public init(
      preAuthorizedCode: String?,

      txCode: TxCode? = nil
    ) {
      self.preAuthorizedCode = preAuthorizedCode
      self.txCode = txCode
    }
  }
  
  public struct Both {
    public let authorizationCode: AuthorizationCode
    public let preAuthorizedCode: PreAuthorizedCode
    
    public init(authorizationCode: AuthorizationCode, preAuthorizedCode: PreAuthorizedCode) {
      self.authorizationCode = authorizationCode
      self.preAuthorizedCode = preAuthorizedCode
    }
  }
}

extension GrantsDTO {
  func toDomain() throws -> Grants {
    if let authorizationCode = authorizationCode,
       let preAuthorizationCode = preAuthorizationCode {
      return .both(
        try Grants.AuthorizationCode(
          issuerState: authorizationCode.issuerState, 
          authorizationServer: URL(string: authorizationCode.authorizationServer ?? "")
        ),
        Grants.PreAuthorizedCode(
          preAuthorizedCode: preAuthorizationCode.preAuthorizedCode,
          txCode: preAuthorizationCode.txCode
        )
      )
      
    } else if let authorizationCode = authorizationCode {
      return .authorizationCode(
        try Grants.AuthorizationCode(
          issuerState: authorizationCode.issuerState, 
          authorizationServer: URL(string: authorizationCode.authorizationServer ?? "")
        )
      )
      
    } else if let preAuthorizationCode = preAuthorizationCode {
      return .preAuthorizedCode(
        Grants.PreAuthorizedCode(
          preAuthorizedCode: preAuthorizationCode.preAuthorizedCode,
          txCode: preAuthorizationCode.txCode
        )
      )
    }
    throw ValidationError.error(reason: "Invalid Grants DTO")
  }
}
