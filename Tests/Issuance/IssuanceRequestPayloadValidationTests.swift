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
@testable import OpenID4VCI

final class IssuanceRequestPayloadValidationTests: XCTestCase {
  
  func testIdentifierBasedPayloadWithAuthorizedIdentifierDoesNotThrow() throws {
    let configurationIdentifier = try CredentialConfigurationIdentifier(value: "config-id")
    let credentialIdentifier = try CredentialIdentifier(value: "credential-id")
    
    let requestPayload = IssuanceRequestPayload.identifierBased(
      credentialConfigurationIdentifier: configurationIdentifier,
      credentialIdentifier: credentialIdentifier
    )
    
    let authorizationDetails: [CredentialConfigurationIdentifier: [CredentialIdentifier]] = [
      configurationIdentifier: [credentialIdentifier]
    ]
    
    XCTAssertNoThrow(
      try Issuer.validateRequestPayload(
        requestPayload: requestPayload,
        authorizationDetails: authorizationDetails
      )
    )
  }
  
  func testIdentifierBasedPayloadWithoutAuthorizedIdentifiersThrows() throws {
    let configurationIdentifier = try CredentialConfigurationIdentifier(value: "config-id")
    let credentialIdentifier = try CredentialIdentifier(value: "credential-id")
    
    let requestPayload = IssuanceRequestPayload.identifierBased(
      credentialConfigurationIdentifier: configurationIdentifier,
      credentialIdentifier: credentialIdentifier
    )
    
    let authorizationDetails: [CredentialConfigurationIdentifier: [CredentialIdentifier]] = [
      configurationIdentifier: []
    ]
    
    XCTAssertThrowsError(
      try Issuer.validateRequestPayload(
        requestPayload: requestPayload,
        authorizationDetails: authorizationDetails
      )
    ) { error in
      XCTAssertValidationError(
        error,
        reason: "No credential identifiers authorized for \(configurationIdentifier)"
      )
    }
  }
  
  func testIdentifierBasedPayloadWithMissingConfigurationAuthorizationThrows() throws {
    let configurationIdentifier = try CredentialConfigurationIdentifier(value: "config-id")
    let otherConfigurationIdentifier = try CredentialConfigurationIdentifier(value: "other-config-id")
    let credentialIdentifier = try CredentialIdentifier(value: "credential-id")
    
    let requestPayload = IssuanceRequestPayload.identifierBased(
      credentialConfigurationIdentifier: configurationIdentifier,
      credentialIdentifier: credentialIdentifier
    )
    
    let authorizationDetails: [CredentialConfigurationIdentifier: [CredentialIdentifier]] = [
      otherConfigurationIdentifier: [credentialIdentifier]
    ]
    
    XCTAssertThrowsError(
      try Issuer.validateRequestPayload(
        requestPayload: requestPayload,
        authorizationDetails: authorizationDetails
      )
    ) { error in
      XCTAssertValidationError(
        error,
        reason: "No credential identifiers authorized for \(configurationIdentifier)"
      )
    }
  }
  
  func testConfigurationBasedPayloadWithAuthorizationDetailsThrows() throws {
    let configurationIdentifier = try CredentialConfigurationIdentifier(value: "config-id")
    let credentialIdentifier = try CredentialIdentifier(value: "credential-id")
    
    let requestPayload = IssuanceRequestPayload.configurationBased(
      credentialConfigurationIdentifier: configurationIdentifier
    )
    
    let authorizationDetails: [CredentialConfigurationIdentifier: [CredentialIdentifier]] = [
      configurationIdentifier: [credentialIdentifier]
    ]
    
    XCTAssertThrowsError(
      try Issuer.validateRequestPayload(
        requestPayload: requestPayload,
        authorizationDetails: authorizationDetails
      )
    ) { error in
      XCTAssertValidationError(
        error,
        reason: "Authorization details of type `openid_credential` require usage of credential identifiers in the credential request"
      )
    }
  }
  
  func testIdentifierBasedPayloadWithUnauthorizedCredentialIdentifierThrows() throws {
    let configurationIdentifier = try CredentialConfigurationIdentifier(value: "config-id")
    let credentialIdentifier = try CredentialIdentifier(value: "credential-id")
    let otherCredentialIdentifier = try CredentialIdentifier(value: "other-credential-id")
    
    let requestPayload = IssuanceRequestPayload.identifierBased(
      credentialConfigurationIdentifier: configurationIdentifier,
      credentialIdentifier: credentialIdentifier
    )
    
    let authorizationDetails: [CredentialConfigurationIdentifier: [CredentialIdentifier]] = [
      configurationIdentifier: [otherCredentialIdentifier]
    ]
    
    XCTAssertThrowsError(
      try Issuer.validateRequestPayload(
        requestPayload: requestPayload,
        authorizationDetails: authorizationDetails
      )
    ) { error in
      XCTAssertValidationError(
        error,
        reason: "Credential identifier \(credentialIdentifier.value) is not among the authorized identifiers: \(authorizationDetails[configurationIdentifier]!)"
      )
    }
  }
  
  func testConfigurationBasedPayloadWithoutAuthorizationDetailsDoesNotThrow() throws {
    let configurationIdentifier = try CredentialConfigurationIdentifier(value: "config-id")
    
    let requestPayload = IssuanceRequestPayload.configurationBased(
      credentialConfigurationIdentifier: configurationIdentifier
    )
    
    XCTAssertNoThrow(
      try Issuer.validateRequestPayload(
        requestPayload: requestPayload,
        authorizationDetails: [:]
      )
    )
  }
}

private extension IssuanceRequestPayloadValidationTests {
  
  func XCTAssertValidationError(
    _ error: Error,
    reason expectedReason: String,
    file: StaticString = #filePath,
    line: UInt = #line
  ) {
    guard case ValidationError.error(let reason) = error else {
      XCTFail("Expected ValidationError.error, got \(error)", file: file, line: line)
      return
    }
    
    XCTAssertEqual(reason, expectedReason, file: file, line: line)
  }
}
