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

/// Enum representing various events related to credential issuance.
public enum CredentialIssuanceEvent {
  
  /// An event indicating that the credential issuance was accepted.
  ///
  /// - Parameters:
  ///   - id: The notification ID associated with the event.
  ///   - description: An optional description of the event.
  case accepted(id: NotificationId, description: String?)
  
  /// An event indicating that the credential issuance failed.
  ///
  /// - Parameters:
  ///   - id: The notification ID associated with the event.
  ///   - description: An optional description of the event.
  case failed(id: NotificationId, description: String?)
  
  /// An event indicating that the issued credential was deleted.
  ///
  /// - Parameters:
  ///   - id: The notification ID associated with the event.
  ///   - description: An optional description of the event.
  case deleted(id: NotificationId, description: String?)
}
