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
import XCTest
import SwiftyJSON

@testable import OpenID4VCI

class EntitiesTests: XCTestCase {
  
  func test() {
    let sdk: OpenID4VCI? = OpenID4VCI()
    
    XCTAssertNotNil(sdk)
  }
}

// MARK: - MsoMdocCredential

class MsoMdocCredentialTests: XCTestCase {
  
  func testInitWhenValidParametersProvided() {
    let expectedFormat = "test-format"
    let expectedDocType = "DrivingLicence"
    let credential = MsoMdocCredential(format: expectedFormat, docType: expectedDocType)
    
    XCTAssertEqual(credential.format, expectedFormat)
    XCTAssertEqual(credential.docType, expectedDocType)
  }
  
  func testCodableWhenEncodedAndDecoded() throws {
    let originalCredential = MsoMdocCredential(format: "test-format", docType: "DrivingLicence")
    let encoder = JSONEncoder()
    let decoder = JSONDecoder()
    let data = try encoder.encode(originalCredential)
    let decodedCredential = try decoder.decode(MsoMdocCredential.self, from: data)
    
    XCTAssertEqual(decodedCredential.format, originalCredential.format)
    XCTAssertEqual(decodedCredential.docType, originalCredential.docType)
  }
  
  func testCodingKeysWhenEncoding() throws {
    let credential = MsoMdocCredential(format: "test-format", docType: "DrivingLicence")
    let encoder = JSONEncoder()
    let data = try encoder.encode(credential)
    let jsonObject = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
    
    XCTAssertNotNil(jsonObject)
    XCTAssertEqual(jsonObject?["format"] as? String, credential.format)
    XCTAssertEqual(jsonObject?["doctype"] as? String, credential.docType)
  }
}

// MARK: - CredentialResponseEncryptionSpecTO
final class CredentialResponseEncryptionSpecTOTests: XCTestCase {
  
  func testInitWhenValidParametersProvided() {
    let jwkJson: JSON = ["key": "value"]
    let expectedAlg = "expectedAlg"
    let expectedEnc = "expectedEnc"
    let spec = CredentialResponseEncryptionSpecTO(
      jwk: jwkJson,
      encryptionAlgorithm: expectedAlg,
      encryptionMethod: expectedEnc
    )
    
    XCTAssertEqual(spec.jwk["key"].stringValue, "value")
    XCTAssertEqual(spec.encryptionAlgorithm, expectedAlg)
    XCTAssertEqual(spec.encryptionMethod, expectedEnc)
  }
}

// MARK: - AuthorizationToken

final class AuthorizationTokenTests: XCTestCase {
  
  func testInitWhenBearerTokenValid() throws {
    let accessToken = "validBearerToken"
    
    let token = try AuthorizationToken(accessToken: accessToken, useDPoP: false)
    
    switch token {
    case .bearer(let tokenValue):
      XCTAssertEqual(tokenValue, accessToken)
    default:
      XCTFail("Expected .bearer case")
    }
  }
  
  func testInitWhenDPoPTokenValid() throws {
    let accessToken = "validDPoPToken"
    let token = try AuthorizationToken(accessToken: accessToken, useDPoP: true)
    
    switch token {
    case .dpop(let tokenValue):
      XCTAssertEqual(tokenValue, accessToken)
    default:
      XCTFail("Expected .dpop case")
    }
  }
  
  func testInitWhenAccessTokenEmpty() {
    let emptyToken = ""
    
    XCTAssertThrowsError(try AuthorizationToken(accessToken: emptyToken, useDPoP: false)) { error in
      guard let validationError = error as? ValidationError else {
        XCTFail("Expected ValidationError")
        return
      }
      switch validationError {
      case .error(let reason):
        XCTAssertEqual(reason, "AuthorizationToken access token cannot be empty")
      default:
        XCTFail("Expected ValidationError.error with reason")
      }
    }
  }
  
  func testCodableWhenBearerTokenEncodedAndDecoded() throws {
    let original = AuthorizationToken.bearer(accessToken: "bearerToken")
    let encoder = JSONEncoder()
    let decoder = JSONDecoder()
    
    let data = try encoder.encode(original)
    let decoded = try decoder.decode(AuthorizationToken.self, from: data)
    
    switch decoded {
    case .bearer(let tokenValue):
      XCTAssertEqual(tokenValue, "bearerToken")
    default:
      XCTFail("Expected .bearer case")
    }
  }
  
  func testCodableWhenDPoPTokenEncodedAndDecoded() throws {
    let original = AuthorizationToken.dpop(accessToken: "dpopToken")
    let encoder = JSONEncoder()
    let decoder = JSONDecoder()
    
    let data = try encoder.encode(original)
    let decoded = try decoder.decode(AuthorizationToken.self, from: data)
    
    switch decoded {
    case .dpop(let tokenValue):
      XCTAssertEqual(tokenValue, "dpopToken")
    default:
      XCTFail("Expected .dpop case")
    }
  }
}

// MARK: - IssuedCertificate

final class IssuedCertificateTests: XCTestCase {
  
  func testInitWhenValidProperties() {
    let certificate = IssuedCertificate(format: "PDF", content: "content")
    XCTAssertEqual(certificate.format, "PDF")
    XCTAssertEqual(certificate.content, "content")
  }
  
  func testEncodeWhenEncodedToJSON() throws {
    let certificate = IssuedCertificate(format: "PDF", content: "content")
    let encoder = JSONEncoder()
    let data = try encoder.encode(certificate)
    
    let json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
    
    XCTAssertEqual(json?["format"] as? String, "PDF")
    XCTAssertEqual(json?["content"] as? String, "content")
  }
  
  func testDecodeWhenJSONDecoded() throws {
    let json = """
    {
      "format": "PDF",
      "content": "content"
    }
    """.data(using: .utf8)!
    
    let decoder = JSONDecoder()
    let certificate = try decoder.decode(IssuedCertificate.self, from: json)
    
    XCTAssertEqual(certificate.format, "PDF")
    XCTAssertEqual(certificate.content, "content")
  }
}

// MARK: - OidCredentialAuthorizationDetails

final class OidCredentialAuthorizationDetailTests: XCTestCase {
  
  func testByCredentialConfigurationWhenInitialized() throws {
    let configId = try CredentialConfigurationIdentifier(value: "test-config")
    let credentialId = try CredentialIdentifier(value: "cred-1")
    let byConfig = ByCredentialConfiguration(
      credentialConfigurationId: configId,
      credentialIdentifiers: [credentialId]
    )
    
    XCTAssertEqual(byConfig.credentialConfigurationId.value, "test-config")
    XCTAssertEqual(byConfig.credentialIdentifiers?.first?.value, "cred-1")
  }
  
  func testByCredentialConfigurationWhenEncodedAndDecoded() throws {
    let configId = try CredentialConfigurationIdentifier(value: "test-config")
    let credentialId = try CredentialIdentifier(value: "cred-1")
    let byConfig = ByCredentialConfiguration(
      credentialConfigurationId: configId,
      credentialIdentifiers: [credentialId]
    )
    
    let data = try JSONEncoder().encode(byConfig)
    let decoded = try JSONDecoder().decode(ByCredentialConfiguration.self, from: data)
    
    XCTAssertEqual(decoded.credentialConfigurationId.value, "test-config")
    XCTAssertEqual(decoded.credentialIdentifiers?.first?.value, "cred-1")
  }
  
  func testByFormatMsoMdocAuthorizationDetails() throws {
    let details = MsoMdocAuthorizationDetails(doctype: "passport")
    let format = ByFormat.msoMdocAuthorizationDetails(details)
    
    let data = try JSONEncoder().encode(format)
    let decoded = try JSONDecoder().decode(ByFormat.self, from: data)
    
    if case .msoMdocAuthorizationDetails(let decodedDetails) = decoded {
      XCTAssertEqual(decodedDetails.doctype, "passport")
    } else {
      XCTFail("Expected .msoMdocAuthorizationDetails case")
    }
  }
  
  func testByFormatSdJwtVcAuthorizationDetailsWhenEncodedAndDecoded() throws {
    let details = SdJwtVcAuthorizationDetails(vct: "vct-value")
    let format = ByFormat.sdJwtVcAuthorizationDetails(details)
    
    let data = try JSONEncoder().encode(format)
    let decoded = try JSONDecoder().decode(ByFormat.self, from: data)
    
    if case .sdJwtVcAuthorizationDetails(let decodedDetails) = decoded {
      XCTAssertEqual(decodedDetails.vct, "vct-value")
    } else {
      XCTFail("Expected .sdJwtVcAuthorizationDetails case")
    }
  }
  
  func testByFormatWhenDecodingUnknownType() throws {
    let json = """
      {
        "type": "unknownType",
        "details": {}
      }
      """.data(using: .utf8)!
    
    XCTAssertThrowsError(try JSONDecoder().decode(ByFormat.self, from: json))
  }
}

// MARK: - BatchCredentialIssuance
final class BatchCredentialIssuanceTests: XCTestCase {
  
  func testInitwithValidBatchSize() throws {
    let issuance = try BatchCredentialIssuance(batchSize: 5)
    XCTAssertEqual(issuance.batchSize, 5)
  }
  
  func testInitWithZeroBatchSize() {
    XCTAssertThrowsError(try BatchCredentialIssuance(batchSize: 0)) { error in
      guard case ValidationError.invalidBatchSize(let size) = error else {
        XCTFail("Expected invalidBatchSize error")
        return
      }
      XCTAssertEqual(size, 0)
    }
  }
  
  func testInitWithNegativeBatchSize() {
    XCTAssertThrowsError(try BatchCredentialIssuance(batchSize: -10)) { error in
      guard case ValidationError.invalidBatchSize(let size) = error else {
        XCTFail("Expected invalidBatchSize error")
        return
      }
      XCTAssertEqual(size, -10)
    }
  }
  
  func testCodableEncodeDecode() throws {
    let issuance = try BatchCredentialIssuance(batchSize: 7)
    
    let encoder = JSONEncoder()
    let data = try encoder.encode(issuance)
    let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
    let decoded = try JSONDecoder().decode(BatchCredentialIssuance.self, from: data)
    
    XCTAssertEqual(json["batch_size"] as? Int, 7)
    
    XCTAssertEqual(decoded.batchSize, 7)
  }
}

// MARK: - OfferedCredential
final class OfferedCredentialTests: XCTestCase {
  
  func makeJSONCredential() -> JSON {
    return JSON(["type": "test"])
  }
  
  func testW3CVerifiableCredentialSignedJwt() throws {
    let signedJwt = SignedJwt(credentialDefinition: makeJSONCredential(), scope: "openid")
    let w3c = W3CVerifiableCredential.signedJwt(signedJwt)
    
    let data = try JSONEncoder().encode(w3c)
    let decoded = try JSONDecoder().decode(W3CVerifiableCredential.self, from: data)
    
    if case let .signedJwt(decodedSignedJwt) = decoded {
      XCTAssertEqual(decodedSignedJwt.scope, "openid")
      XCTAssertEqual(decodedSignedJwt.credentialDefinition["type"].stringValue, "test")
    } else {
      XCTFail("Expected .signedJwt case")
    }
  }
  
  func testW3CVerifiableCredentialJSONLdSignedJwt() throws {
    let jsonLd = JsonLdSignedJwt(credentialDefinition: makeJSONCredential(), scope: "scope")
    let w3c = W3CVerifiableCredential.jsonLdSignedJwt(jsonLd)
    
    let data = try JSONEncoder().encode(w3c)
    let decoded = try JSONDecoder().decode(W3CVerifiableCredential.self, from: data)
    
    if case let .jsonLdSignedJwt(decodedJsonLd) = decoded {
      XCTAssertEqual(decodedJsonLd.scope, "scope")
      XCTAssertEqual(decodedJsonLd.credentialDefinition["type"].stringValue, "test")
    } else {
      XCTFail("Expected .jsonLdSignedJwt case")
    }
  }
  
  func testW3CVerifiableCredentialDecodeInvalid() {
    let invalidJSON = "{}".data(using: .utf8)!
    
    XCTAssertThrowsError(try JSONDecoder().decode(W3CVerifiableCredential.self, from: invalidJSON)) { error in
      guard case DecodingError.dataCorrupted = error else {
        XCTFail("Expected DecodingError.dataCorrupted")
        return
      }
    }
  }
}
