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

public enum JSONParseError: LocalizedError {
  case fileNotFound(filename: String)
  case dataInitialisation(Error)
  case jsonSerialization(Error)
  case mappingFail(value: String, toType: String)
  case invalidJSON
  case invalidJWT
  case notSupportedOperation

  public var errorDescription: String? {
    switch self {
    case .fileNotFound(let filename):
      return ".fileNotFound \(filename)"
    case .dataInitialisation(let error):
      return ".dataInitialisation \(error.localizedDescription)"
    case .jsonSerialization(let error):
      return ".jsonSerialization \(error.localizedDescription)"
    case .mappingFail(let value, let toType):
      return ".mappingFail from: \(value) to: \(toType)"
    case .invalidJSON:
      return ".invalidJSON"
    case .invalidJWT:
      return ".invalidJWT"
    case .notSupportedOperation:
      return ".notSupportedOperation"
    }
  }
}
