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

public struct Display: Codable, Equatable, Sendable {
  public let name: String?
  public let locale: Locale?
  public let logo: Logo?
  public let description: String?
  public let backgroundColor: String?
  public let backgroundImage: BackgroundImage?
  public let textColor: String?
  
  enum CodingKeys: String, CodingKey {
    case name
    case locale
    case logo
    case description
    case backgroundColor = "background_color"
    case backgroundImage = "background_image"
    case textColor = "text_color"
  }
  
  public init(
    name: String?,
    locale: String? = nil,
    logo: Logo? = nil,
    description: String? = nil,
    backgroundColor: String? = nil,
    backgroundImage: BackgroundImage? = nil,
    textColor: String? = nil
  ) {
    self.name = name
    self.locale = Locale(identifier: locale ?? "en_US")
    self.logo = logo
    self.description = description
    self.backgroundColor = backgroundColor
    self.backgroundImage = backgroundImage
    self.textColor = textColor
  }
  
  public init(
    name: String?,
    locale: Locale? = nil,
    logo: Logo? = nil,
    description: String? = nil,
    backgroundColor: String? = nil,
    backgroundImage: BackgroundImage? = nil,
    textColor: String? = nil
  ) {
    self.name = name
    self.locale = locale
    self.logo = logo
    self.description = description
    self.backgroundColor = backgroundColor
    self.backgroundImage = backgroundImage
    self.textColor = textColor
  }
}

public extension Display {

  /// Display metadata for the credential's logo.
  ///
  /// - Important: `uri` is a remote URL controlled by the credential issuer. Loading it
  ///   at display or presentation time gives the issuer a passive usage beacon: they
  ///   observe the holder's IP address, timestamp, and user agent every time the wallet
  ///   renders the credential, and can trivially generate a unique URL per credential
  ///   instance to correlate views. Wallet apps SHOULD fetch the logo at issuance time,
  ///   store the bytes locally, and render from the local copy. Do NOT bind this URL
  ///   directly into an `AsyncImage`/`Image` at presentation time.
  struct Logo: Codable, Equatable, Sendable {
    /// Remote URL to the credential logo, as declared by the issuer's metadata.
    ///
    /// - Warning: See the `Logo` type documentation for the privacy implications of
    ///   loading this URL at display or presentation time.
    public let uri: URL?
    public let alternativeText: String?
    
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
    
    public init(json: JSON) {
      var uri: URL?
      if let urlString = json["uri"].string {
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
      description: json["description"].stringValue,
      backgroundColor: json["background_color"].stringValue,
      backgroundImage: try? .init(json: json["background_image"]),
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
    backgroundImage = try container.decodeIfPresent(BackgroundImage.self, forKey: .backgroundImage)
    textColor = try container.decodeIfPresent(String.self, forKey: .textColor)
  }
  
  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encodeIfPresent(name, forKey: .name)
    try container.encodeIfPresent(locale?.identifier ?? "en_us", forKey: .locale)
    try container.encodeIfPresent(logo, forKey: .logo)
    try container.encodeIfPresent(description, forKey: .description)
    try container.encodeIfPresent(backgroundColor, forKey: .backgroundColor)
    try container.encodeIfPresent(backgroundImage, forKey: .backgroundImage)
    try container.encodeIfPresent(textColor, forKey: .textColor)
  }
}
