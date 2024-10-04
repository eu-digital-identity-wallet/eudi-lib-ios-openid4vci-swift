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

public enum IdentityAndAccessManagementMetadata {
  case oidc(OIDCProviderMetadata)
  case oauth(AuthorizationServerMetadata)
  
  var issuer: String? {
    switch self {
    case .oidc(let metaData):
      return metaData.issuer
    case .oauth(let metaData):
      return metaData.issuer
    }
  }
  
  var authorizationServerSupportsPar: Bool {
    switch self {
    case .oidc(let metaData):
      return metaData.pushedAuthorizationRequestEndpoint != nil
    case .oauth(let metaData):
      return metaData.pushedAuthorizationRequestEndpoint != nil
    }
  }
  
  var pushedAuthorizationRequestEndpointURI: URL? {
    switch self {
    case .oidc(let metaData):
      if let pushedAuthorizationRequestEndpoint = metaData.pushedAuthorizationRequestEndpoint {
        return URL(string: pushedAuthorizationRequestEndpoint)
      }
      return nil
    case .oauth(let metaData):
      if let pushedAuthorizationRequestEndpoint = metaData.pushedAuthorizationRequestEndpoint {
        return URL(string: pushedAuthorizationRequestEndpoint)
      }
      return nil
    }
  }
  
  var authorizationEndpointURI: URL? {
    switch self {
    case .oidc(let metaData):
      return URL(string: metaData.authorizationEndpoint ?? "")
    case .oauth(let metaData):
      return URL(string: metaData.authorizationEndpoint ?? "")
    }
  }
}
