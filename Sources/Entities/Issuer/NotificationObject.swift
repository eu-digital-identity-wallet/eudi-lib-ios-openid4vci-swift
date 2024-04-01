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

public struct NotificationId: Codable {
  public let value: String
  
  public init(value: String) throws {
    guard !value.isEmpty else {
      throw ValidationError.error(reason: "Empty NotificationId")
    }
    self.value = value
  }
}

public struct NotificationObject {
  public let id: NotificationId
  public let event: NotifiedEvent
  public let eventDescription: String?
  
  public init(
    id: NotificationId,
    event: NotifiedEvent,
    eventDescription: String?
  ) {
    self.id = id
    self.event = event
    self.eventDescription = eventDescription
  }
}

public enum NotifiedEvent: String {
  case credentialAccepted = "CREDENTIAL_ACCEPTED"
  case credentialFailure = "CREDENTIAL_FAILURE"
  case credentialDeleted = "CREDENTIAL_DELETED"
}

extension NotificationObject {
  func toDictionary() -> [String: Any] {
    var dictionary: [String: Any] = [
      "id": id.value,
      "event": event.rawValue
    ]
    if let eventDescription = eventDescription {
      dictionary["eventDescription"] = eventDescription
    }
    return dictionary
  }
}
