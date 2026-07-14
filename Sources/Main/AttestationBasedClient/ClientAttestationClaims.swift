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
@preconcurrency import JOSESwift
@preconcurrency import SwiftyJSON

public struct NonBlankString: Sendable, Hashable, CustomStringConvertible {
  public let value: String

  public init(_ value: String) throws {
    guard !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
      throw ClientAttestationError.blankClaim(name: "<unknown>")
    }
    self.value = value
  }

  public init(_ value: String, claimName: String) throws {
    guard !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
      throw ClientAttestationError.blankClaim(name: claimName)
    }
    self.value = value
  }

  public var description: String { value }
}

public struct ConfirmationClaim: Sendable {
  public let jwk: JWK

  public init(jwk: JWK) throws {
    guard jwk.isPublicKey else {
      throw ClientAttestationError.cnfJwkNotPublic
    }
    self.jwk = jwk
  }
}

public struct StatusListTokenClaim: Sendable {
  public let index: Int
  public let uri: NonBlankString

  public init(index: Int, uri: NonBlankString) throws {
    guard index >= 0 else {
      throw ClientAttestationError.invalidStatusListReference(reason: "`idx` must be non-negative")
    }
    self.index = index
    self.uri = uri
  }
}

public struct StatusClaim: Sendable {
  public let statusList: StatusListTokenClaim

  public init(statusList: StatusListTokenClaim) {
    self.statusList = statusList
  }
}

public struct ClientStatusClaim: Sendable {
  public let status: StatusClaim
  public let expiresAt: Date

  public init(status: StatusClaim, expiresAt: Date) {
    self.status = status
    self.expiresAt = expiresAt
  }
}

/// `wallet_solution_certification_information` — TS3 leaves the inner schema open-ended,
/// so the value is exposed as a generic JSON element.
public typealias WalletSolutionCertificationInformation = JSON

public struct ClientAttestationJWTClaims: Sendable {
  public let issuer: NonBlankString
  public let subject: NonBlankString
  public let expirationTime: Date
  public let confirmation: ConfirmationClaim
  public let issuedAt: Date?
  public let notBefore: Date?
  public let walletName: NonBlankString
  public let walletLink: NonBlankString?
  public let status: StatusClaim?
  public let walletVersion: NonBlankString
  public let walletSolutionCertificationInformation: WalletSolutionCertificationInformation
  public let clientStatus: ClientStatusClaim

  public init(
    issuer: NonBlankString,
    subject: NonBlankString,
    expirationTime: Date,
    confirmation: ConfirmationClaim,
    issuedAt: Date?,
    notBefore: Date?,
    walletName: NonBlankString,
    walletLink: NonBlankString?,
    status: StatusClaim?,
    walletVersion: NonBlankString,
    walletSolutionCertificationInformation: WalletSolutionCertificationInformation,
    clientStatus: ClientStatusClaim
  ) {
    self.issuer = issuer
    self.subject = subject
    self.expirationTime = expirationTime
    self.confirmation = confirmation
    self.issuedAt = issuedAt
    self.notBefore = notBefore
    self.walletName = walletName
    self.walletLink = walletLink
    self.status = status
    self.walletVersion = walletVersion
    self.walletSolutionCertificationInformation = walletSolutionCertificationInformation
    self.clientStatus = clientStatus
  }
}

// MARK: - Parsing from JSON payload

extension ClientAttestationJWTClaims {

  static func parse(payload: JSON) throws -> ClientAttestationJWTClaims {
    // iss — required, non-blank
    guard let issString = payload[JWTClaimNames.issuer].string else {
      throw ClientAttestationError.missingIssuerClaim
    }
    let issuer = try NonBlankString(issString, claimName: JWTClaimNames.issuer)

    // sub — required, non-blank
    guard let subString = payload[JWTClaimNames.subject].string else {
      throw ClientAttestationError.missingSubject
    }
    let subject = try NonBlankString(subString, claimName: JWTClaimNames.subject)

    // exp — required
    guard let expSeconds = payload[JWTClaimNames.expirationTime].double else {
      throw ClientAttestationError.missingExpirationClaim
    }
    let expirationTime = Date(timeIntervalSince1970: expSeconds)

    // cnf — required, must contain public JWK
    guard payload[JWTClaimNames.cnf].dictionary != nil else {
      throw ClientAttestationError.missingCnfClaim
    }
    let cnfJson = payload[JWTClaimNames.cnf]
    guard cnfJson[JWTClaimNames.JWK].dictionary != nil else {
      throw ClientAttestationError.missingJwkClaim
    }
    let jwk = try Self.parseJWK(from: cnfJson[JWTClaimNames.JWK])
    let confirmation = try ConfirmationClaim(jwk: jwk)

    // iat — optional
    let issuedAt: Date? = payload[JWTClaimNames.issuedAt].double.map(Date.init(timeIntervalSince1970:))

    // nbf — optional
    let notBefore: Date? = payload[JWTClaimNames.notBefore].double.map(Date.init(timeIntervalSince1970:))

    // wallet_name — required, non-blank
    guard let walletNameString = payload[JWTClaimNames.walletName].string else {
      throw ClientAttestationError.missingWalletName
    }
    let walletName = try NonBlankString(walletNameString, claimName: JWTClaimNames.walletName)

    // wallet_link — optional, non-blank when present
    let walletLink: NonBlankString?
    if let walletLinkString = payload[JWTClaimNames.walletLink].string {
      walletLink = try NonBlankString(walletLinkString, claimName: JWTClaimNames.walletLink)
    } else {
      walletLink = nil
    }

    // status — optional top-level status
    let status: StatusClaim?
    if payload[JWTClaimNames.status].dictionary != nil {
      status = try Self.parseStatusClaim(from: payload[JWTClaimNames.status])
    } else {
      status = nil
    }

    // wallet_version — required, non-blank
    guard let walletVersionString = payload[JWTClaimNames.walletVersion].string else {
      throw ClientAttestationError.missingWalletVersion
    }
    let walletVersion = try NonBlankString(walletVersionString, claimName: JWTClaimNames.walletVersion)

    // wallet_solution_certification_information — required, any JSON shape
    let wsci = payload[JWTClaimNames.walletSolutionCertificationInformation]
    guard wsci.exists() && wsci.type != .null else {
      throw ClientAttestationError.missingWalletSolutionCertificationInformation
    }

    // client_status — required
    guard payload[JWTClaimNames.clientStatus].dictionary != nil else {
      throw ClientAttestationError.missingClientStatus
    }
    let clientStatus = try Self.parseClientStatus(from: payload[JWTClaimNames.clientStatus])

    return ClientAttestationJWTClaims(
      issuer: issuer,
      subject: subject,
      expirationTime: expirationTime,
      confirmation: confirmation,
      issuedAt: issuedAt,
      notBefore: notBefore,
      walletName: walletName,
      walletLink: walletLink,
      status: status,
      walletVersion: walletVersion,
      walletSolutionCertificationInformation: wsci,
      clientStatus: clientStatus
    )
  }

  private static func parseJWK(from json: JSON) throws -> JWK {
    let data: Data
    do {
      data = try json.rawData()
    } catch {
      throw ClientAttestationError.invalidJwk(reason: "cannot serialize jwk")
    }
    if let ec = try? ECPublicKey(data: data) {
      return ec
    }
    if let rsa = try? RSAPublicKey(data: data) {
      return rsa
    }
    throw ClientAttestationError.invalidJwk(reason: "unsupported key type")
  }

  private static func parseStatusClaim(from json: JSON) throws -> StatusClaim {
    guard json[JWTClaimNames.statusList].dictionary != nil else {
      throw ClientAttestationError.invalidStatusListReference(reason: "missing `status_list`")
    }
    let listJson = json[JWTClaimNames.statusList]
    guard let idx = listJson[JWTClaimNames.idx].int else {
      throw ClientAttestationError.invalidStatusListReference(reason: "missing or non-integer `idx`")
    }
    guard let uriString = listJson[JWTClaimNames.uri].string else {
      throw ClientAttestationError.invalidStatusListReference(reason: "missing `uri`")
    }
    let uri = try NonBlankString(uriString, claimName: JWTClaimNames.uri)
    let listRef = try StatusListTokenClaim(index: idx, uri: uri)
    return StatusClaim(statusList: listRef)
  }

  private static func parseClientStatus(from json: JSON) throws -> ClientStatusClaim {
    guard json[JWTClaimNames.status].dictionary != nil else {
      throw ClientAttestationError.invalidClientStatus(reason: "missing `status`")
    }
    let status = try Self.parseStatusClaim(from: json[JWTClaimNames.status])

    guard let expSeconds = json[JWTClaimNames.expirationTime].double else {
      throw ClientAttestationError.invalidClientStatus(reason: "missing `exp`")
    }
    return ClientStatusClaim(
      status: status,
      expiresAt: Date(timeIntervalSince1970: expSeconds)
    )
  }
}
