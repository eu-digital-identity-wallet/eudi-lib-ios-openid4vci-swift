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

public final class ClientAuthenticationMethod: Hashable {
  // MARK: - Properties
  public let value: String
  
  // MARK: - Static Constants
  public static let clientSecretBasic = ClientAuthenticationMethod("client_secret_basic")
  public static let clientSecretPost = ClientAuthenticationMethod("client_secret_post")
  public static let clientSecretJWT = ClientAuthenticationMethod("client_secret_jwt")
  public static let privateKeyJWT = ClientAuthenticationMethod("private_key_jwt")
  public static let tlsClientAuth = ClientAuthenticationMethod("tls_client_auth")
  public static let selfSignedTlsClientAuth = ClientAuthenticationMethod("self_signed_tls_client_auth")
  public static let requestObject = ClientAuthenticationMethod("request_object")
  public static let none = ClientAuthenticationMethod("none")
  
  // MARK: - Initializer
  public init(_ value: String) {
    self.value = value
  }
  
  // MARK: - Default Method
  public static func getDefault() -> ClientAuthenticationMethod {
    return .clientSecretBasic
  }
  
  // MARK: - Parsing Method
  public static func parse(_ value: String) -> ClientAuthenticationMethod {
    switch value.lowercased() {
    case clientSecretBasic.value:
      return .clientSecretBasic
    case clientSecretPost.value:
      return .clientSecretPost
    case clientSecretJWT.value:
      return .clientSecretJWT
    case privateKeyJWT.value:
      return .privateKeyJWT
    case tlsClientAuth.value.lowercased():
      return .tlsClientAuth
    case selfSignedTlsClientAuth.value.lowercased():
      return .selfSignedTlsClientAuth
    case requestObject.value.lowercased():
      return .requestObject
    case none.value:
      return .none
    default:
      return ClientAuthenticationMethod(value)
    }
  }
  
  // MARK: - Hashable
  public static func == (lhs: ClientAuthenticationMethod, rhs: ClientAuthenticationMethod) -> Bool {
    return lhs.value == rhs.value
  }
  
  public func hash(into hasher: inout Hasher) {
    hasher.combine(value)
  }
  
  // MARK: - Custom Description
  public var description: String {
    return value
  }
}

