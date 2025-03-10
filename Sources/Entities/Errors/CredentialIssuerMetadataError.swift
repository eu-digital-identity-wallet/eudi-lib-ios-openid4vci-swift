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

enum CredentialIssuerMetadataError: Error {
  case unableToFetchCredentialIssuerMetadata(cause: Error)
  case nonParseableCredentialIssuerMetadata(cause: Error)
  
  /**
    * Indicates the Credential Issuer does not provide signed metadata.
    */
  case missingSignedMetadata

  /**
   * Indicates the signed metadata of the Credential Issuer are not valid.
   */
  case invalidSignedMetadata(String)
  
  func toException() -> CredentialIssuerMetadataException {
    return CredentialIssuerMetadataException(error: self)
  }
  
  func raise() throws {
    throw self.toException()
  }
}

struct CredentialIssuerMetadataException: Error {
  let error: CredentialIssuerMetadataError
}

