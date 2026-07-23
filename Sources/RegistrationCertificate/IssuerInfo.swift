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


public struct IssuerInfo: Sendable, Equatable, Decodable {

  public let attestations: [IssuerInfoAttestation]

  public init(attestations: [IssuerInfoAttestation]) {
    self.attestations = attestations
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()

    if let array = try? container.decode([IssuerInfoAttestation].self) {
      self.attestations = array
      return
    }

    if let single = try? container.decode(IssuerInfoAttestation.self) {
      self.attestations = [single]
      return
    }

    if let jwtString = try? container.decode(String.self), !jwtString.isEmpty {
      // Tolerant: bare JWT string is treated as a WRPRC attestation.
      self.attestations = [
        IssuerInfoAttestation(
          format: ETSI119472Part3.REGISTRATION_CERT,
          data: jwtString
        )
      ]
      return
    }

    throw DecodingError.dataCorruptedError(
      in: container,
      debugDescription: "issuer_info must be an attestation object, an array of attestation objects, or a bare JWT string"
    )
  }
}

/// A single entry inside `issuer_info` — declares its `format` and carries the
/// attestation `data` (for WRPRC, a compact-serialized signed JWT).
public struct IssuerInfoAttestation: Sendable, Equatable, Decodable {

  public let format: String
  public let data: String

  public init(format: String, data: String) {
    self.format = format
    self.data = data
  }

  private enum CodingKeys: String, CodingKey {
    case format
    case data
  }
}
