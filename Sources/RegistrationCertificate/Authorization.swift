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

/// Outcome of a WRPRC policy evaluation performed by the consumer-supplied
/// `RegistrationCertificatePolicy.authorize` closure.
///
/// - `.granted` — the policy is satisfied. `warnings` may be empty (clean pass)
///   or contain non-blocking violations the caller should be told about.
/// - `.notGranted` — the policy is not satisfied. Carries a single blocking
///   `PolicyViolation` describing why. The library propagates this via
///   `WRPRCError.policyNotMet(...)` and refuses to construct an `Issuer`.
public enum Authorization: Sendable, Equatable {
  case granted(warnings: [PolicyViolation])
  case notGranted(error: PolicyViolation)
}
