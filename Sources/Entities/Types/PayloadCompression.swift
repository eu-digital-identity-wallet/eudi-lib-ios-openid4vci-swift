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

/// Represents payload compression support.
public enum PayloadCompression: Codable, Equatable, Sendable {
  
  /// Compression not supported.
  case notSupported
  
  /// Compression supported with the given algorithms.
  case supported([CompressionAlgorithm])
  
  public init(_ algorithms: [CompressionAlgorithm]?) {
    if let algs = algorithms, !algs.isEmpty {
      self = .supported(algs)
    } else {
      self = .notSupported
    }
  }
}

