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

/// Wallet configuration for credential reuse policies
public enum SupportedCredentialReusePolicies: Sendable, Equatable {
  /// Wallet supports these reuse policies but does not mandate their presence in issuer metadata.
  /// If issuer has no policy, credential issuance continues normally.
  /// If issuer has policy, wallet tries to match; fails if no common policy found.
  case supported(Set<ReuseMethod>)

  /// Wallet requires that issuer defines at least one of these reuse policies.
  /// If issuer has no policy → issuance fails with error.
  /// If issuer has policy, wallet tries to match; fails if no common policy found.
  case required(Set<ReuseMethod>)

  /// Wallet does not support credential reuse policies at all.
  /// If issuer has policy → credential issuance continues normally
  case notSupported

  
  public func validate() throws {
    switch self {
    case .supported(let methods), .required(let methods):
      guard !methods.isEmpty else {
        throw CredentialReusePolicyError.invalidPolicyStructure(
          "policyTypes cannot be empty"
        )
      }

      let hasBaseMethod = methods.contains(.onceOnly) || methods.contains(.limitedTime)
      guard hasBaseMethod else {
        throw CredentialReusePolicyError.invalidPolicyStructure(
          "policyTypes must contain at least onceOnly or limitedTime"
        )
      }

    case .notSupported:
      // No validation needed
      break
    }
  }

  public func supports(_ method: ReuseMethod) -> Bool {
    switch self {
    case .supported(let methods), .required(let methods):
      return methods.contains(method)
    case .notSupported:
      return false
    }
  }

  public var supportedMethods: Set<ReuseMethod>? {
    switch self {
    case .supported(let methods), .required(let methods):
      return methods
    case .notSupported:
      return nil
    }
  }

  public var isRequired: Bool {
    switch self {
    case .required:
      return true
    case .supported, .notSupported:
      return false
    }
  }
}
