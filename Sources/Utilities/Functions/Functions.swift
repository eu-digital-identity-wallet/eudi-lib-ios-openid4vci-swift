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

public func convertToJsonString(dictionary: [String: Any]) -> String? {
  do {
    let jsonData = try JSONSerialization.data(withJSONObject: dictionary, options: [])
    let jsonString = String(data: jsonData, encoding: .utf8)
    return jsonString
  } catch {
    print("Error converting dictionary to JSON string: \(error)")
    return nil
  }
}

public func unwrapOrThrow<T>(_ optional: T?, error: Error) throws -> T {
  guard let unwrapped = optional else {
    throw error
  }
  return unwrapped
}
