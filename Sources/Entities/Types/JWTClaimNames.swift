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

public struct JWTClaimNames {

  // RFC 7519 "iss" (Issuer) Claim
  public static let issuer = "iss"

  // RFC 7519 "sub" (Subject) Claim
  public static let subject = "sub"

  // RFC 7519 "aud" (Audience) Claim
  public static let audience = "aud"

  // RFC 7519 "exp" (Expiration Time) Claim
  public static let expirationTime = "exp"

  // RFC 7519 "nbf" (Not Before) Claim
  public static let notBefore = "nbf"

  // RFC 7519 "iat" (Issued At) Claim
  public static let issuedAt = "iat"

  // RFC 7519 "jti" (JWT ID) Claim
  public static let jwtId = "jti"

  private init() {}
}

public extension JWTClaimNames {
  static let nonce = "nonce"
  static let htm = "htm"
  static let htu = "htu"
}
