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
import XCTest
import SwiftyJSON
import JOSESwift

@testable import OpenID4VCI

final class CertifacteAndKeysTests: XCTestCase {
  
  func testPublicKeyFromValidRSAPEM() {
    let publicKey = SecCertificateHelper().publicKey(fromPem: rsaPemString)
    XCTAssertNotNil(publicKey, "Public key should not be nil for a valid certificate")
  }
  
  func testPublicKeyFromValidECPEM() {
    
    let publicKey = SecCertificateHelper().publicKey(fromPem: ecPemString)
    XCTAssertNotNil(publicKey, "Public key should not be nil for a valid certificate")
  }
  
  func testPublicKeyFromInvalidPEM() {
    let invalidPemString = "Invalid PEM Data"
    
    let publicKey = SecCertificateHelper().publicKey(fromPem: invalidPemString)
    XCTAssertNil(publicKey, "Public key should be nil for an invalid certificate")
  }
  
  func testPublicKeyAlgorithmFromValidRSAPEM() {
    let publicKey = SecCertificateHelper().publicKey(fromPem: rsaPemString)
    XCTAssertNotNil(publicKey, "Public key should not be nil for a valid certificate")
    
    let algorithm = publicKey!.keyAlgorithm()
    
    XCTAssert(algorithm == "RSA")
  }
  
  func testPublicKeyAlgorithmFromValidECPEM() {
    
    let publicKey = SecCertificateHelper().publicKey(fromPem: ecPemString)
    XCTAssertNotNil(publicKey, "Public key should not be nil for a valid certificate")
    
    let algorithm = publicKey!.keyAlgorithm()
    
    XCTAssert(algorithm == "EC")
  }
  
  func testCertificateChainValidation() {
    
    _ = SecCertificateHelper.validateCertificateChain(
      certificates: certificateChain
    )
  }
}

let rsaPemString = """
      -----BEGIN CERTIFICATE-----
      MIICEjCCAXsCAg36MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwGA1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNEREMRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdlYiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIwODIyMDUyNjU0WhcNMTcwODIxMDUyNjU0WjBKMQswCQYDVQQGEwJKUDEOMAwGA1UECAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEAm/xmkHmEQrurE/0re/jeFRLl8ZPjBop7uLHhnia7lQG/5zDtZIUC3RVpqDSwBuw/NTweGyuP+o8AG98HxqxTBwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBABS2TLuBeTPmcaTaUW/LCB2NYOy8GMdzR1mx8iBIu2H6/E2tiY3RIevV2OW61qY2/XRQg7YPxx3ffeUugX9F4J/iPnnu1zAxxyBy2VguKv4SWjRFoRkIfIlHX0qVviMhSlNy2ioFLy7JcPZb+v3ftDGywUqcBiVDoea0Hn+GmxZA
      -----END CERTIFICATE-----
      """

let ecPemString = """
      -----BEGIN CERTIFICATE-----
      MIIDLTCCArKgAwIBAgIUL8s5Ts635k6OhrRFMlsSRASYo6YwCgYIKoZIzj0EAwIwXDEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAtIFVUIDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMB4XDTI0MTEyOTExMjgzNVoXDTI2MTEyOTExMjgzNFowaTEdMBsGA1UEAwwURVVESSBSZW1vdGUgVmVyaWZpZXIxDDAKBgNVBAUTAzAwMTEtMCsGA1UECgwkRVVESSBXYWxsZXQgUmVmZXJlbmNlIEltcGxlbWVudGF0aW9uMQswCQYDVQQGEwJVVDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAWa9Uar7oP1ZbGFbsFA4g31PzNGZcwh2vR7PCkk0YiAL4chrslg9cj1kBynyZi7nZrYgPOJ7x0atRFdkxfXjtCjggFDMIIBPzAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFLNsuJEXHNekGmYxh0Lhi8BAzJUbMCcGA1UdEQQgMB6CHGRldi5pc3N1ZXItYmFja2VuZC5ldWRpdy5kZXYwEgYDVR0lBAswCQYHKIGMXQUBBjBDBgNVHR8EPDA6MDigNqA0hjJodHRwczovL3ByZXByb2QucGtpLmV1ZGl3LmRldi9jcmwvcGlkX0NBX1VUXzAxLmNybDAdBgNVHQ4EFgQU8eHA/MXvkyCF4Q1iouXP0spiMUgwDgYDVR0PAQH/BAQDAgeAMF0GA1UdEgRWMFSGUmh0dHBzOi8vZ2l0aHViLmNvbS9ldS1kaWdpdGFsLWlkZW50aXR5LXdhbGxldC9hcmNoaXRlY3R1cmUtYW5kLXJlZmVyZW5jZS1mcmFtZXdvcmswCgYIKoZIzj0EAwIDaQAwZgIxAJjKSA3A7kYOBYwJCOOcrcaRCDeVTfcvYYCR8AjynUi25I/tksDCFA5+maCLfmkUKQIxAOVjGsgluQwTN50o97WmilHblW4N8+qArmsBC8jTIutnKfc4yZ3u5Q1uZYIlbtKSrg==
      -----END CERTIFICATE-----
      """

let certificateChain = [ "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"].compactMap { SecCertificateHelper.createCertificate(fromPEM: $0) }
