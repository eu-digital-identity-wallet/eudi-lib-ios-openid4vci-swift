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

public class JWEAlgorithm: JOSEAlgorithm {

  public init(_ type: AlgorithmType) {
    super.init(name: type.name, requirement: type.requirement)
  }

  public override init(name: String) {
    super.init(name: name)
  }

  public override init(name: String, requirement: JOSEAlgorithm.Requirement) {
    super.init(name: name, requirement: requirement)
  }
  
  required init(from decoder: Decoder) throws {
    try super.init(from: decoder)
  }
}

public extension JWEAlgorithm {
  static func parse(_ s: String) -> JWEAlgorithm {
    if let type = AlgorithmType(rawValue: s) {
      return .init(type)
    }
    return .init(name: s)
  }
}

public extension JWEAlgorithm {
  enum AlgorithmType: String {
    case RSA1_5 = "RSA1_5"
    case RSA_OAEP = "RSA-OAEP"
    case RSA_OAEP_256 = "RSA-OAEP-256"
    case RSA_OAEP_384 = "RSA-OAEP-384"
    case RSA_OAEP_512 = "RSA-OAEP-512"
    case A128KW = "A128KW"
    case A192KW = "A192KW"
    case A256KW = "A256KW"
    case DIR = "dir"
    case ECDH_ES = "ECDH-ES"
    case ECDH_ES_A128KW = "ECDH-ES+A128KW"
    case ECDH_ES_A192KW = "ECDH-ES+A192KW"
    case ECDH_ES_A256KW = "ECDH-ES+A256KW"
    case ECDH_1PU = "ECDH-1PU"
    case ECDH_1PU_A128KW = "ECDH-1PU+A128KW"
    case ECDH_1PU_A192KW = "ECDH-1PU+A192KW"
    case ECDH_1PU_A256KW = "ECDH-1PU+A256KW"
    case A128GCMKW = "A128GCMKW"
    case A192GCMKW = "A192GCMKW"
    case A256GCMKW = "A256GCMKW"
    case PBES2_HS256_A128KW = "PBES2-HS256+A128KW"
    case PBES2_HS384_A192KW = "PBES2-HS384+A192KW"
    case PBES2_HS512_A256KW = "PBES2-HS512+A256KW"
  
    var name: String {
      return self.rawValue
    }
  
    var requirement: Requirement {
      switch self {
      case .RSA1_5:
        return .REQUIRED
      case .RSA_OAEP:
        return .OPTIONAL
      case .RSA_OAEP_256:
        return .OPTIONAL
      case .RSA_OAEP_384:
        return .OPTIONAL
      case .RSA_OAEP_512:
        return .OPTIONAL
      case .A128KW:
        return .RECOMMENDED
      case .A192KW:
        return .OPTIONAL
      case .A256KW:
        return .RECOMMENDED
      case .DIR:
        return .RECOMMENDED
      case .ECDH_ES:
        return .RECOMMENDED
      case .ECDH_ES_A128KW:
        return .RECOMMENDED
      case .ECDH_ES_A192KW:
        return .OPTIONAL
      case .ECDH_ES_A256KW:
        return .RECOMMENDED
      case .ECDH_1PU:
        return .OPTIONAL
      case .ECDH_1PU_A128KW:
        return .OPTIONAL
      case .ECDH_1PU_A192KW:
        return .OPTIONAL
      case .ECDH_1PU_A256KW:
        return .OPTIONAL
      case .A128GCMKW:
        return .OPTIONAL
      case .A192GCMKW:
        return .OPTIONAL
      case .A256GCMKW:
        return .OPTIONAL
      case .PBES2_HS256_A128KW:
        return .OPTIONAL
      case .PBES2_HS384_A192KW:
        return .OPTIONAL
      case .PBES2_HS512_A256KW:
        return .OPTIONAL
      }
    }
  }
}

public extension JWEAlgorithm {
  class Family: JOSEAlgorithmFamily<JWEAlgorithm> {}
}

public extension JWEAlgorithm.Family {

  enum FamilyType {
    case RSA
    case AES_KW
    case ECDH_ES
    case ECDH_1PU
    case AES_GCM_KW
    case PBES2
    case ASYMMETRIC
    case SYMMETRIC
  }

  static func parse(_ type: FamilyType) -> JWEAlgorithm.Family {
  
    var RSA: [JWEAlgorithm] {
      return [
        .init(.RSA1_5),
        .init(.RSA_OAEP),
        .init(.RSA_OAEP_256),
        .init(.RSA_OAEP_384),
        .init(.RSA_OAEP_512)
      ]
    }
  
    var ECDH_ES: [JWEAlgorithm] {
      return [
        .init(.ECDH_ES),
        .init(.ECDH_ES_A128KW),
        .init(.ECDH_ES_A192KW),
        .init(.ECDH_ES_A256KW)
      ]
    }
  
    var AES_KW: [JWEAlgorithm] {
      return [
        .init(.A128KW),
        .init(.A192KW),
        .init(.A256KW)
      ]
    }
  
    var AES_GCM_KW: [JWEAlgorithm] {
      return [
        .init(.A128GCMKW),
        .init(.A192GCMKW),
        .init(.A256GCMKW)
      ]
    }
  
    var ASYMMETRIC: [JWEAlgorithm] {
      return RSA + ECDH_ES
    }
  
    var SYMMETRIC: [JWEAlgorithm] {
      return AES_KW + AES_GCM_KW + [.init(.DIR)]
    }
  
    switch type {
    case .RSA:
      return .init(RSA)
    case .AES_KW:
      return .init(AES_KW)
    case .ECDH_ES:
      return .init(ECDH_ES)
    case .ECDH_1PU:
      return .init(
        .init(.ECDH_1PU),
        .init(.ECDH_1PU_A128KW),
        .init(.ECDH_1PU_A192KW),
        .init(.ECDH_1PU_A256KW)
      )
    case .AES_GCM_KW:
      return .init(AES_GCM_KW)
    case .PBES2:
      return .init(
        .init(.PBES2_HS256_A128KW),
        .init(.PBES2_HS384_A192KW),
        .init(.PBES2_HS512_A256KW)
      )
    case .ASYMMETRIC:
      return .init(ASYMMETRIC)
    case .SYMMETRIC:
      return .init(SYMMETRIC)
    }
  }
}

public extension KeyManagementAlgorithm {
  init?(algorithm: JWEAlgorithm) {
    self.init(rawValue: algorithm.name)
  }
}
