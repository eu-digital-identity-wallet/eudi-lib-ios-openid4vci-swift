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

public protocol NotifyIssuerType {
  func notify(authorizedRequest: AuthorizedRequest, notification: NotificationObject) async throws -> Result<Void, Error>
}

public class NotifyIssuer: NotifyIssuerType {
  private let issuanceRequester: IssuanceRequester
  
  public init(
    issuerMetadata: CredentialIssuerMetadata,
    poster: PostingType
  ) {
    self.issuanceRequester = IssuanceRequester(
      issuerMetadata: issuerMetadata,
      poster: poster
    )
  }
  
  public func notify(
    authorizedRequest: AuthorizedRequest,
    notification: NotificationObject
  ) async throws -> Result<Void, Error> {
    
    do {
      return try await issuanceRequester.notifyIssuer(
        accessToken: authorizedRequest.accessToken,
        notification: notification
      )
    } catch {
      throw error
    }
  }
}
