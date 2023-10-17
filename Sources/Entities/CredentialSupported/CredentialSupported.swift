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

public enum CredentialSupported {
  
  /// The data of a W3C Verifiable Credential issued as a signed JWT, not using JSON-LD.
  case w3CVerifiableCredentialCredentialSupported(jwtVcJson: W3CVerifiableCredentialSignedJwtCredentialSupported)
  
  /// The data of a W3C Verifiable Credential issued as a signed JWT using JSON-LD.
  case w3CVerifiableCredentialCredentialSupported(jwtVcJsonLd: W3CVerifiableCredentialJsonLdSignedJwtCredentialSupported)
  
  /// The data of a W3C Verifiable Credential issued as using Data Integrity and JSON-LD.
  case w3CVerifiableCredentialCredentialSupported(ldpVc: W3CVerifiableCredentialsJsonLdDataIntegrityCredentialSupported)
  
  /// The data of a Verifiable Credentials issued as an ISO mDL.
  case w3CVerifiableCredentialCredentialSupported(isoMdl: MsoMdocCredentialCredentialSupported)
}
