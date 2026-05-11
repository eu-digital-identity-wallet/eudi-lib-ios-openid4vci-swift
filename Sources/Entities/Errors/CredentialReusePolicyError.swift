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

/// Errors related to credential reuse policy validation and processing
public enum CredentialReusePolicyError: LocalizedError {
  case invalidPolicyStructure(String)
  case unsupportedPolicyId(String)
  case missingRequiredField(String)
  case invalidDetailsCombination([ReuseMethod])
  case batchSizeMismatch(required: Int, provided: Int)
  case noSupportedPolicyFound
  case unsupportedReuseMethod(ReuseMethod)

  public var errorDescription: String? {
    switch self {
    case .invalidPolicyStructure(let reason):
      return "Invalid credential reuse policy structure: \(reason)"
    case .unsupportedPolicyId(let id):
      return "Unsupported policy ID: \(id). Expected 'arf_annex_ii'"
    case .missingRequiredField(let field):
      return "Missing required field: \(field)"
    case .invalidDetailsCombination(let methods):
      return "Invalid details combination: \(methods.map { $0.rawValue })"
    case .batchSizeMismatch(let required, let provided):
      return "Batch size mismatch. Required: \(required), Provided: \(provided)"
    case .noSupportedPolicyFound:
      return "No supported reuse policy found in issuer metadata"
    case .unsupportedReuseMethod(let method):
      return "Reuse method '\(method.rawValue)' is not supported in this version"
    }
  }
}
