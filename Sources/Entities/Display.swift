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

public struct Display: Codable, Equatable {
  public let name: String?
  public let locale: String?
  let logo: Logo?
  let description: String?
  let backgroundColor: String?
  let textColor: String?
  
  enum CodingKeys: String, CodingKey {
    case name
    case locale
    case logo
    case description
    case backgroundColor = "background_color"
    case textColor = "text_color"
  }
  
  public init(
    name: String?,
    locale: String? = nil,
    logo: Logo? = nil,
    description: String? = nil,
    backgroundColor: String? = nil,
    textColor: String? = nil
  ) {
    self.name = name
    self.locale = locale
    self.logo = logo
    self.description = description
    self.backgroundColor = backgroundColor
    self.textColor = textColor
  }
}

public extension Display {
  
  struct Logo: Codable, Equatable {
    let url: URL?
    let alternativeText: String?
    
    enum CodingKeys: String, CodingKey {
      case url
      case alternativeText = "alt_text"
    }
    
    public init(
      url: URL? = nil,
      alternativeText: String? = nil
    ) {
      self.url = url
      self.alternativeText = alternativeText
    }
    
    public init(from decoder: Decoder) throws {
      let container = try decoder.container(keyedBy: CodingKeys.self)
      if let urlString = try? container.decode(String.self, forKey: .url) {
        url = URL(string: urlString)
      } else {
        url = nil
      }
      alternativeText = try? container.decode(String.self, forKey: .alternativeText)
    }
  }
}
