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

public enum ClaimPathError: Error {
  case emptyClaimPath
  case invalidJsonPointerFormat(String)
  case elementNotFound(ClaimPath)
}

/// A structure representing a path in a hierarchical claim structure.
public struct ClaimPath: Equatable, Hashable, Sendable {
  /// The list of elements representing the path.
  public let value: [ClaimPathElement]
  
  /// Initializes a `ClaimPath` ensuring it is not empty.
  /// - Parameter value: An array of `ClaimPathElement` representing the path.
  public init(_ value: [ClaimPathElement]) {
    self.value = value
  }
  
  /// Returns a string representation of the claim path.
  public var description: String {
    return value.description
  }
  
  /// Appends a `ClaimPathElement` to the current path.
  public static func + (lhs: ClaimPath, rhs: ClaimPathElement) -> ClaimPath {
    return ClaimPath(lhs.value + [rhs])
  }
  
  /// Merges two `ClaimPath` instances into a single path.
  public static func + (lhs: ClaimPath, rhs: ClaimPath) -> ClaimPath {
    return ClaimPath(lhs.value + rhs.value)
  }
  
  /// Checks if the current path contains another path.
  /// - Parameter that: The `ClaimPath` to compare against.
  /// - Returns: `true` if `that` is contained within `self`, otherwise `false`.
  public func contains(_ that: ClaimPath) -> Bool {
    guard that.value.count <= self.value.count else { return false }
    return zip(self.value, that.value).allSatisfy { (selfElement, thatElement) in
      selfElement.contains(thatElement)
    }
  }
  
  /// Appends a wild-card indicator (`ClaimPathElement.allArrayElements`).
  public func allArrayElements() -> ClaimPath {
    return self + .allArrayElements
  }
  
  /// Appends an indexed path (`ClaimPathElement.arrayElement`).
  public func arrayElement(_ index: Int) -> ClaimPath {
    return self + .arrayElement(index: index)
  }
  
  /// Appends a named path (`ClaimPathElement.claim`).
  public func claim(_ name: String) -> ClaimPath {
    return self + .claim(name: name)
  }
  
  /// Retrieves the parent path of the current `ClaimPath`.
  /// - Returns: The parent `ClaimPath` if it exists, otherwise `nil`.
  public func parent() -> ClaimPath? {
    guard !value.isEmpty else { return nil }
    let newValue = Array(value.dropLast())
    return newValue.isEmpty ? nil : ClaimPath(newValue)
  }
  
  /// Retrieves the first element of the claim path.
  public func head() -> ClaimPathElement {
    return value.first!
  }
  
  /// Retrieves the tail of the claim path (all elements except the first).
  /// - Returns: A new `ClaimPath` without the first element, or `nil` if empty.
  public func tail() -> ClaimPath? {
    let tailElements = Array(value.dropFirst())
    return tailElements.isEmpty ? nil : ClaimPath(tailElements)
  }
  
  /// Retrieves the head element.
  public func component1() -> ClaimPathElement {
    return head()
  }
  
  /// Retrieves the tail path.
  public func component2() -> ClaimPath? {
    return tail()
  }
  
  /// Creates a `ClaimPath` from a single claim name.
  /// - Parameter name: The name of the claim.
  /// - Returns: A `ClaimPath` containing a single `ClaimPathElement.claim`.
  public static func claim(_ name: String) -> ClaimPath {
    return ClaimPath([.claim(name: name)])
  }
}

public enum ClaimPathElement: Equatable, Hashable, Sendable {
  /// Indicates that all elements of the currently selected array(s) are to be selected.
  /// It is represented as `nil` when serialized.
  case allArrayElements
  
  /// Indicates that a specific index in an array is to be selected.
  /// The index must be non-negative.
  case arrayElement(index: Int)
  
  /// Indicates that a specific key is to be selected.
  /// The key is represented as a string.
  case claim(name: String)
  
  /// Checks whether the current instance contains the other.
  public func contains(_ other: ClaimPathElement) -> Bool {
    switch (self, other) {
    case (.allArrayElements, .allArrayElements): return true
    case (.allArrayElements, .arrayElement): return true
    case (.allArrayElements, .claim): return false
    case (.arrayElement(let index1), .arrayElement(let index2)): return index1 == index2
    case (.claim(let name1), .claim(let name2)): return name1 == name2
    default: return false
    }
  }
  
  /// Returns a string representation of the element.
  public var description: String {
    switch self {
    case .allArrayElements: return "null"
    case .arrayElement(let index): return "\(index)"
    case .claim(let name): return name
    }
  }
  
  /// Helper function to apply different closures based on the case.
  public func fold<T>(
    ifAllArrayElements: () -> T,
    ifArrayElement: (Int) -> T,
    ifClaim: (String) -> T
  ) -> T {
    switch self {
    case .allArrayElements: return ifAllArrayElements()
    case .arrayElement(let index): return ifArrayElement(index)
    case .claim(let name): return ifClaim(name)
    }
  }
}

extension ClaimPath: Decodable {
  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    let jsonArray = try container.decode([JSON].self)
    
    let elements = try jsonArray.map { json in
      if let intValue = json.int {
        return ClaimPathElement.arrayElement(index: intValue)
      } else if json.null != nil {
        return ClaimPathElement.allArrayElements
      } else if let stringValue = json.string {
        return ClaimPathElement.claim(name: stringValue)
      } else {
        throw DecodingError.dataCorruptedError(
          in: container,
          debugDescription: "Invalid ClaimPathElement type"
        )
      }
    }
    
    self.init(elements)
  }
}
