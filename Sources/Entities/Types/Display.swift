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

public struct Display: Codable, Equatable {
  public let name: String?
  public let locale: Locale?
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
    self.locale = Locale(identifier: locale ?? "en_US")
    self.logo = logo
    self.description = description
    self.backgroundColor = backgroundColor
    self.textColor = textColor
  }
  
  public init(
    name: String?,
    locale: Locale? = nil,
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
    let uri: URL?
    let alternativeText: String?
    
    enum CodingKeys: String, CodingKey {
      case uri
      case alternativeText = "alt_text"
    }
    
    public init(
      uri: URL? = nil,
      alternativeText: String? = nil
    ) {
      self.uri = uri
      self.alternativeText = alternativeText
    }
    
    public init(from decoder: Decoder) throws {
      let container = try decoder.container(keyedBy: CodingKeys.self)
      if let urlString = try? container.decode(String.self, forKey: .uri) {
        uri = URL(string: urlString)
      } else {
        uri = nil
      }
      alternativeText = try? container.decode(String.self, forKey: .alternativeText)
    }
    
    init(json: JSON) {
      var uri: URL?
      if let urlString = json["url"].string {
        uri = URL(string: urlString)
      } else {
        uri = nil
      }
      
      self.init(
        uri: uri,
        alternativeText: json["alt_text"].string
      )
    }
  }
  
  init(json: JSON) {
    self.init(
      name: json["name"].stringValue,
      locale: json["locale"].stringValue,
      logo: .init(json: json["logo"]),
      description:json["description"].stringValue,
      backgroundColor: json["background_color"].stringValue,
      textColor: json["text_color"].stringValue
    )
  }
  
  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    name = try container.decodeIfPresent(String.self, forKey: .name)
    
    let localeString = try container.decodeIfPresent(String.self, forKey: .locale)
    locale = Locale(identifier: localeString ?? "en_us")
    
    logo = try container.decodeIfPresent(Logo.self, forKey: .logo)
    description = try container.decodeIfPresent(String.self, forKey: .description)
    backgroundColor = try container.decodeIfPresent(String.self, forKey: .backgroundColor)
    textColor = try container.decodeIfPresent(String.self, forKey: .textColor)
  }
  
  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encodeIfPresent(name, forKey: .name)
    try container.encodeIfPresent(locale?.identifier ?? "en_us", forKey: .locale)
    try container.encodeIfPresent(logo, forKey: .logo)
    try container.encodeIfPresent(description, forKey: .description)
    try container.encodeIfPresent(backgroundColor, forKey: .backgroundColor)
    try container.encodeIfPresent(textColor, forKey: .textColor)
  }
}
