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
import SwiftyJSON
import JOSESwift

public struct CredentialRequestEncryptionSpec {
  public let selectedJWK: JWK
  public let encryptionMethod: JOSEEncryptionMethod
  public let compressionMethod: CompressionAlgorithm?
  
  public init(
    selectedJWK: JWK,
    encryptionMethod: JOSEEncryptionMethod,
    compressionMethod: CompressionAlgorithm? = nil
  ) {
    self.selectedJWK = selectedJWK
    self.encryptionMethod = encryptionMethod
    self.compressionMethod = compressionMethod
  }
}

public struct CredentialRequestEncryptionSpecTO: Codable {
  public let kid: String  
  public let encryptionMethod: String
  public let compressionMethod: String?
  
  public init(
    kid: String,
    encryptionMethod: String,
    compressionMethod: String? = nil
  ) {
    self.kid = kid
    self.encryptionMethod = encryptionMethod
    self.compressionMethod = compressionMethod
  }
  
  private enum CodingKeys: String, CodingKey {
    case kid
    case encryptionMethod = "enc"
    case compressionMethod = "zip"
  }
}
