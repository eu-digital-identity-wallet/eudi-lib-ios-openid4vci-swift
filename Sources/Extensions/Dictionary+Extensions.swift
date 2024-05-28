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

public extension Dictionary where Key == String, Value == Any {
  
  func toThrowingJSONData() throws -> Data {
    return try JSONSerialization.data(withJSONObject: self, options: [])
  }
  
  // Creates a dictionary from a JSON file in the specified bundle
  static func from(bundle name: String) -> Result<Self, JSONParseError> {
    let fileType = "json"
    guard let path = Bundle.module.path(forResource: name, ofType: fileType) else {
      return .failure(.fileNotFound(filename: name))
    }
    return from(JSONfile: URL(fileURLWithPath: path))
  }
  
  // Converts the dictionary to an array of URLQueryItem objects
  func toQueryItems() -> [URLQueryItem] {
    var queryItems: [URLQueryItem] = []
    for (key, value) in self {
      if let stringValue = value as? String {
        queryItems.append(URLQueryItem(name: key, value: stringValue))
      } else if let numberValue = value as? NSNumber {
        queryItems.append(URLQueryItem(name: key, value: numberValue.stringValue))
      } else if let arrayValue = value as? [Any] {
        let arrayQueryItems = arrayValue.compactMap { (item) -> URLQueryItem? in
          guard let stringValue = item as? String else { return nil }
          return URLQueryItem(name: key, value: stringValue)
        }
        queryItems.append(contentsOf: arrayQueryItems)
      }
    }
    return queryItems
  }
  
  func getValue<T: Codable>(
    for key: String,
    error: LocalizedError
  ) throws -> T {
    guard let value = self[key] as? T else {
      throw error
    }
    return value
  }
  
  var jsonData: Data? {
    return try? JSONSerialization.data(withJSONObject: self, options: [.prettyPrinted])
  }
  
  func toJSONString() -> String? {
    if let jsonData = jsonData {
      let jsonString = String(data: jsonData, encoding: .utf8)
      return jsonString
    }
    return nil
  }
  
  static func from(JSONfile url: URL) -> Result<Self, JSONParseError> {
    let data: Data
    do {
      data = try Data(contentsOf: url)
    } catch let error {
      return .failure(.dataInitialisation(error))
    }
    
    let jsonObject: Any
    do {
      jsonObject = try JSONSerialization.jsonObject(with: data, options: .mutableLeaves)
    } catch let error {
      return .failure(.jsonSerialization(error))
    }
    
    guard let jsonResult = jsonObject as? Self else {
      return .failure(.mappingFail(
        value: String(describing: jsonObject),
        toType: String(describing: Self.Type.self)
      ))
    }
    
    return .success(jsonResult)
  }
  
  func convertToDictionaryOfStrings() -> [Key: String] {
    var stringDictionary: [Key: String] = [:]
    
    for (key, value) in self {
      if let stringValue = value as? String {
        stringDictionary[key] = stringValue
      } else {
        stringDictionary[key] = JSON(value).stringValue
      }
    }
    
    return stringDictionary
  }
  
  func convertToDictionaryOfStrings(excludingKeys: [String]) -> [Key: String] {
    var stringDictionary: [Key: String] = [:]
    
    for (key, value) in self {
      
      if excludingKeys.contains(where: { $0 == key }) {
        continue
      }
      
      if let stringValue = value as? String {
        stringDictionary[key] = stringValue
      } else {
        stringDictionary[key] = JSON(value).stringValue
      }
    }
    
    return stringDictionary
  }
  
  func containsAll(_ keys: [Key]) -> Bool {
    let keySet = Set(keys)
    let dictionaryKeySet = Set(self.keys)
    return keySet.isSubset(of: dictionaryKeySet)
  }
}
