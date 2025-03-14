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
    let publicKey = SecCertificate.publicKey(fromPem: rsaPemString)
    XCTAssertNotNil(publicKey, "Public key should not be nil for a valid certificate")
  }
  
  func testPublicKeyFromValidECPEM() {
    
    let publicKey = SecCertificate.publicKey(fromPem: ecPemString)
    XCTAssertNotNil(publicKey, "Public key should not be nil for a valid certificate")
  }
  
  func testPublicKeyFromInvalidPEM() {
    let invalidPemString = "Invalid PEM Data"
    
    let publicKey = SecCertificate.publicKey(fromPem: invalidPemString)
    XCTAssertNil(publicKey, "Public key should be nil for an invalid certificate")
  }
  
  func testPublicKeyAlgorithmFromValidRSAPEM() {
    let publicKey = SecCertificate.publicKey(fromPem: rsaPemString)
    XCTAssertNotNil(publicKey, "Public key should not be nil for a valid certificate")
    
    let algorithm = publicKey!.keyAlgorithm()
    
    XCTAssert(algorithm == "RSA")
  }
  
  func testPublicKeyAlgorithmFromValidECPEM() {
    
    let publicKey = SecCertificate.publicKey(fromPem: ecPemString)
    XCTAssertNotNil(publicKey, "Public key should not be nil for a valid certificate")
    
    let algorithm = publicKey!.keyAlgorithm()
    
    XCTAssert(algorithm == "EC")
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
