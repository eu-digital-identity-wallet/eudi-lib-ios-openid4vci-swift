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

public struct X509Certificate {}

public enum BindingKey {
  
  // JWK Binding Key
  case jwk(algorithm: JWSAlgorithm, jwk: JWK)
  
  // DID Binding Key
  case did(identity: String)
  
  // X509 Binding Key
  case x509(certificate: X509Certificate)
}

protocol RequestIssuance {
  
  // Request single issuance without proof
  func requestSingle(with request: AuthorizedRequest, credentialMetadata: CredentialMetadata, claimSet: ClaimSet?) async throws -> Result<SubmittedRequest, Error>
  
  // Request single issuance with proof
  func requestSingle(with request: AuthorizedRequest, credentialMetadata: CredentialMetadata, claimSet: ClaimSet?, bindingKey: BindingKey) async throws -> Result<SubmittedRequest, Error>
  
  // Request batch issuance without proof
  func requestBatch(with request: AuthorizedRequest, credentialsMetadata: [(CredentialMetadata, ClaimSet?)]) async throws -> Result<SubmittedRequest, Error>
  
  // Request batch issuance with proof
  func requestBatch(with request: AuthorizedRequest, credentialsMetadata: [(CredentialMetadata, ClaimSet?, BindingKey)]) async throws -> Result<SubmittedRequest, Error>
  
  // Handle invalid proof
  func handleInvalidProof(with request: AuthorizedRequest, cNonce: CNonce) async throws -> AuthorizedRequest
}
