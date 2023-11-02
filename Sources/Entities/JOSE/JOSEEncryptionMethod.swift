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

public class JOSEEncryptionMethod: JOSEAlgorithm {
  
  public private(set) var cekBitLength: Int = 0
  
  public init(_ type: EncryptionMethodType) {
    let options = type.options
    super.init(name: type.name, requirement: options.requirement)
    self.cekBitLength = options.cekBitLength
  }
  
  public override init(name: String) {
    super.init(name: name)
  }
  
  public override init(name: String, requirement: JOSEAlgorithm.Requirement) {
    super.init(name: name, requirement: requirement)
  }
  
  public init(
    name: String,
    requirement: JOSEAlgorithm.Requirement,
    cekBitLength: Int
  ) {
    super.init(name: name, requirement: requirement)
    self.cekBitLength = cekBitLength
  }
  
  required init(from decoder: Decoder) throws {
    try super.init(from: decoder)
  }
}

public extension JOSEEncryptionMethod {
  static func parse(_ s: String) -> JOSEEncryptionMethod {
    if let type = EncryptionMethodType(rawValue: s) {
      return .init(type)
    }
    return .init(name: s)
  }
}

public extension JOSEEncryptionMethod {
  enum EncryptionMethodType: String {
    case A128CBC_HS256 = "A128CBC-HS256"
    case A192CBC_HS384 = "A192CBC-HS384"
    case A256CBC_HS512 = "A256CBC-HS512"
    case A128GCM = "A128GCM"
    case A192GCM = "A192GCM"
    case A256GCM = "A256GCM"
    case XC20P = "XC20P"
    
    var name: String {
      return self.rawValue
    }
    
    var options: (requirement: Requirement, cekBitLength: Int) {
      switch self {
      case .A128CBC_HS256:
        return (.REQUIRED, 256)
      case .A192CBC_HS384:
        return (.OPTIONAL, 384)
      case .A256CBC_HS512:
        return (.REQUIRED, 512)
      case .A128GCM:
        return (.RECOMMENDED, 128)
      case .A192GCM:
        return (.OPTIONAL, 192)
      case .A256GCM:
        return (.RECOMMENDED, 256)
      case .XC20P:
        return (.OPTIONAL, 256)
      }
    }
  }
}

public extension JOSEEncryptionMethod {
  class Family: JOSEAlgorithmFamily<JOSEEncryptionMethod> {}
}

public extension JOSEEncryptionMethod.Family {
  
  enum JoseEncryptionMethodFamilyType {
    case AES_CBC_HMAC_SHA
    case AES_GCM
  }
  
  static func parse(_ type: JoseEncryptionMethodFamilyType) -> JOSEEncryptionMethod.Family {
    switch type {
    case .AES_CBC_HMAC_SHA:
      return .init(
        .init(.A128CBC_HS256),
        .init(.A192CBC_HS384),
        .init(.A256CBC_HS512)
      )
    case .AES_GCM:
      return .init(
        .init(.A128GCM),
        .init(.A192GCM),
        .init(.A256GCM)
      )
    }
  }
}

public extension ContentEncryptionAlgorithm {
  init?(encryptionMethod: JOSEEncryptionMethod) {
    self.init(rawValue: encryptionMethod.name)
  }
}

