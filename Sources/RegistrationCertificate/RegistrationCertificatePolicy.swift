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

/// Configuration that drives WRP Registration Certificate (WRPRC) enforcement during
/// issuance authorization.
///
public struct RegistrationCertificatePolicy: Sendable {

  /// Signature of the consumer-supplied WRPRC policy validation function.
  ///
  /// - Parameters:
  ///   - wrpac: The WRP Access Certificate (base64 DER — a single X.509 leaf
  ///     certificate) that signed the issuer metadata.
  ///   - wrprc: The raw WRPRC value as delivered in `issuer_info`, opaque to the
  ///     library (typically a compact-serialized JWT).
  ///   - offeredConfigurations: The credential configurations referenced by the
  ///     resolved `CredentialOffer`.
  /// - Returns: An `Authorization` — either `.granted(warnings:)` or 
  ///   `.notGranted(error:)`. `.notGranted` causes the authorizer to throw
  ///   `WRPRCError.policyNotMet(...)`.
  public typealias Authorize = @Sendable (
    _ wrpac: String,
    _ wrprc: String,
    _ offeredConfigurations: [CredentialConfigurationIdentifier: CredentialSupported]
  ) async -> Authorization

  public let authorize: Authorize

  public init(authorize: @escaping Authorize) {
    self.authorize = authorize
  }
}
