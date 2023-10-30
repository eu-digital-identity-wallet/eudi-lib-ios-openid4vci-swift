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

public struct AuthorizationCode {
  public let issuerState: String?
  
  public init(issuerState: String? = nil) {
    self.issuerState = issuerState
  }
}

public struct PreAuthorizedCode {
  public let preAuthorizedCode: String
  public let pinRequired: Bool
  public let interval: TimeInterval
  
  public init(
    preAuthorizedCode: String,
    pinRequired: Bool = false,
    interval: TimeInterval = 5.0
  ) {
    self.preAuthorizedCode = preAuthorizedCode
    self.pinRequired = pinRequired
    self.interval = interval
  }
}

public enum Grants {
  case authorizationCode(AuthorizationCode)
  case preAuthorizedCode(PreAuthorizedCode)
  case both(AuthorizationCode, PreAuthorizedCode)
}
