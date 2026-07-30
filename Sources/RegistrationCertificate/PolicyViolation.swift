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

/// A single WRP Registration Certificate policy violation produced by the
/// consumer-supplied `RegistrationCertificatePolicy.authorize` closure.
///
/// The **outcome** (grant vs deny) is expressed by `Authorization`, not by this
/// type. `Authorization.granted(warnings: [PolicyViolation])` carries any
/// non-blocking violations; `Authorization.notGranted(error: PolicyViolation)`
/// carries a single blocking violation.
public struct PolicyViolation: Sendable, Equatable {
  public let value: String

  public init(_ value: String) {
    precondition(!value.isEmpty, "PolicyViolation.value must not be empty")
    self.value = value
  }
}
