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

public class JOSEAlgorithmFamily<T: JOSEAlgorithm>: Equatable {

  public static func == (lhs: JOSEAlgorithmFamily<T>, rhs: JOSEAlgorithmFamily<T>) -> Bool {
    return lhs.algorithms == rhs.algorithms
  }

  private var algorithms: [T]

  init(_ algorithms: T...) {
    self.algorithms = algorithms
  }

  init(_ algorithms: [T]) {
    self.algorithms = algorithms
  }
}

public extension JOSEAlgorithmFamily {
  func append(_ item: T) {
    self.algorithms.append(item)
  }

  func all() -> [T] {
    return self.algorithms
  }

  func clear() {
    self.algorithms = []
  }
  
  func contains(_ item: T) -> Bool {
    self.algorithms.contains(where: { $0 == item })
  }
}
