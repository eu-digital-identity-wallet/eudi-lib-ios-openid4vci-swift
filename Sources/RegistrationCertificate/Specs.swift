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


public enum ETSI119472Part3 {
  /// The `issuer_info` member on the Credential Issuer Metadata.
  public static let ISSUER_INFO = "issuer_info"

  /// The `format` member on each `issuer_info` attestation entry.
  public static let FORMAT = "format"

  /// The `data` member on each `issuer_info` attestation entry.
  public static let DATA = "data"

  /// Format identifier for a WRP Registration Certificate attestation carried inside `issuer_info`.
  public static let REGISTRATION_CERT = "registration_cert"
}

/// Constants from ETSI TS 119 475 v1.1.1 (WRP Registration Certificate).
public enum ETSI119475 {
  /// JWS header `typ` value for a WRP Registration Certificate.
  public static let REG_CERT_HEADER_TYPE = "rc-wrp+jwt"
}
