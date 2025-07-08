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

internal enum Either<A: Codable, B: Codable>: Codable {
  case left(A)
  case right(B)

  init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()

    if let a = try? container.decode(A.self) {
      self = .left(a)
    } else if let b = try? container.decode(B.self) {
      self = .right(b)
    } else {
      throw DecodingError.typeMismatch(
        Either<A, B>.self,
        DecodingError.Context(
          codingPath: decoder.codingPath,
          debugDescription: "Data didn't match either A or B"
        )
      )
    }
  }
}
