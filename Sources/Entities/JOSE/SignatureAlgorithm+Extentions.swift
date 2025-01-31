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
import JOSESwift

public extension SignatureAlgorithm {
  /// Returns `true` if the algorithm is NOT a MAC-based algorithm (HMAC).
  var isNotMacAlgorithm: Bool {
    switch self {
    case .HS256, .HS384, .HS512:
      return false  // These are HMAC algorithms
    default:
      return true   // All other algorithms are not MAC-based
    }
  }
}

