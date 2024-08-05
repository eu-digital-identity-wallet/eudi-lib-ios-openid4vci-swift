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
import SwiftyJSON
import XCTest
@testable import OpenID4VCI

final class FormPostTests: XCTestCase {

  func testMethodIsSetToPOST() throws {
    let formPost = try FormPost(
      url: URL(string: "http://example.com")!,
      contentType: .form,
      formData: [:]
    )
    XCTAssertEqual(formPost.method, .POST)
    XCTAssertEqual(formPost.urlRequest.httpMethod, "POST")
  }

  func testURLIsSetToRequest() throws {
    let formPost = try FormPost(
      url: URL(string: "http://example.com")!,
      contentType: .form,
      formData: [:]
    )
    XCTAssertEqual(formPost.url, URL(string: "http://example.com")!)
    XCTAssertEqual(formPost.urlRequest.url, URL(string: "http://example.com")!)
  }

  func testContentTypeIsSetInRequestHeaders() throws {
    let formPost = try FormPost(
      url: URL(string: "http://example.com")!,
      contentType: .form,
      formData: [:]
    )
    XCTAssertEqual(formPost.urlRequest.allHTTPHeaderFields, ["Content-Type" : "application/x-www-form-urlencoded"])

    let jsonPost = try FormPost(
      url: URL(string: "http://example.com")!,
      contentType: .json,
      formData: [:]
    )
    XCTAssertEqual(jsonPost.urlRequest.allHTTPHeaderFields, ["Content-Type" : "application/json"])
  }

  func testAdditionalHeadersAreSetToRequest() throws {
    let formPost = try FormPost(
      url: URL(string: "http://example.com")!,
      contentType: .json,
      additionalHeaders: ["Content-Encoding": "gzip"],
      formData: [:]
    )
    XCTAssertEqual(
      formPost.urlRequest.allHTTPHeaderFields,
      ["Content-Type" : "application/json", "Content-Encoding" : "gzip"]
    )
  }

  func testAdditionalHeadersOverrideContentType() throws {
    let formPost = try FormPost(
      url: URL(string: "http://example.com")!,
      contentType: .json,
      additionalHeaders: ["Content-Encoding": "gzip", "Content-Type": "myapp/json"],
      formData: [:]
    )
    XCTAssertEqual(
      formPost.urlRequest.allHTTPHeaderFields,
      ["Content-Type" : "myapp/json", "Content-Encoding" : "gzip"]
    )
  }

  func testEmptyFormDataProducesEmptyFormBodyToRequest() throws {
    let formPost = try FormPost(
      url: URL(string: "http://example.com")!,
      contentType: .form,
      formData: [:]
    )
    XCTAssertEqual(formPost.body, Data())
    XCTAssertEqual(formPost.urlRequest.httpBody, Data())
  }

  func testFormDataIsEncodedToRequestBody() throws {
    let formPost = try FormPost(
      url: URL(string: "http://example.com")!,
      contentType: .form,
      formData: [
        "foo": "bar",
        "num": 42,
        "float": 3.14,
        "": ""
      ]
    )
    let encodedData = FormBodyData(content: [
      ("foo", "bar"),
      ("num", "42"),
      ("float", "3.14"),
      ("", "")
    ])
    XCTAssertEqual(FormBodyData(data: formPost.body!), encodedData)
    XCTAssertEqual(formPost.urlRequest.httpBody, formPost.body)
  }

  func testFormDataWithSpecialCharactesIsEncodedToRequestBody() throws {
    let formPost = try FormPost(
      url: URL(string: "http://example.com")!,
      contentType: .form,
      formData: [
        "&foo": "=bar?\r\n",
        "allowed": "_*_-_._",
        "biz": "café",
        "tags": "t0 t1 t2"
      ]
    )
    let encodedData = FormBodyData(content: [
      ("%26foo", "%3Dbar%3F%0D%0A"),
      ("allowed", "_*_-_._"),
      ("biz", "caf%C3%A9"),
      ("tags", "t0+t1+t2")
    ])
    XCTAssertEqual(FormBodyData(data: formPost.body!), encodedData)
    XCTAssertEqual(formPost.urlRequest.httpBody, formPost.body)
  }

  func testArrayInFormDataIsEncodedAsMultipleValuesWithSameName() throws {
    let formPost = try FormPost(
      url: URL(string: "http://example.com")!,
      contentType: .form,
      formData: [
        "multi": [1, 3.14, "foo", "café", nil],
      ]
    )
    let encodedData = FormBodyData(content: [
      ("multi", "1"),
      ("multi", "3.14"),
      ("multi", "foo"),
      ("multi", "caf%C3%A9"),
      ("multi", "")
    ])
    XCTAssertEqual(FormBodyData(data: formPost.body!), encodedData)
    XCTAssertEqual(formPost.urlRequest.httpBody, formPost.body)
  }

  func testEmptyFormDataProducesEmptyObjectJSONBodyToRequest() throws {
    let formPost = try FormPost(
      url: URL(string: "http://example.com")!,
      contentType: .json,
      formData: [:]
    )
    XCTAssertEqual(formPost.body, "{}".data(using: .utf8))
    XCTAssertEqual(formPost.urlRequest.httpBody, "{}".data(using: .utf8))
  }

  func testJSONDataIsEncodedToRequestBody() throws {
    let formPost = try FormPost(
      url: URL(string: "http://example.com")!,
      contentType: .json,
      formData: [
        "foo": "bar",
        "biz": "café",
        "num": 42,
        "float": 3.14,
        "bool": true,
        "special": "/\\\"\t\r\n",
        "arr": [1, 2],
        "obj": [
          "sub": "val"
        ]
      ]
    )
    let encoded = """
        {
          "foo": "bar",
          "biz": "café",
          "num": 42,
          "float": 3.14,
          "bool": true,
          "special" : "\\/\\\\\\"\\t\\r\\n",
          "arr": [1, 2],
          "obj": { "sub": "val" }
        }
        """
    XCTAssertEqual(try JSON(data: formPost.body!), JSON(parseJSON: encoded))
  }

  func testUnsupportedFormDataValueThrows() throws {
    struct S {}
    let value = S()
    XCTAssertThrowsError(
      try FormPost(
        url: URL(string: "http://example.com")!,
        contentType: .form,
        formData: ["unsupported": value]
      )
    ) { error in
      guard case FormPost.FormURLEncodingError.unsupportedValue = error else {
        XCTFail("Unexpected \(error)")
        return
      }
    }
  }

}

private struct FormBodyData: Equatable {
  private let content: [(key: String, value: String)]

  init(content: [(key: String, value: String)]) {
    self.content = content
  }

  init(data: Data) {
    self.init(
      content: String(data: data, encoding: .ascii)!
        .split(separator: "&")
        .map { $0.split(separator: "=", maxSplits: 2, omittingEmptySubsequences: false) }
        .map { (String($0[0]), String($0[1])) }
        .reduce(into: []) { bodyData, keyValue in
          bodyData.append(keyValue)
        }
    )
  }

  func contains(key: String, value: String) -> Bool {
    content.firstIndex(where: { (k, v) in k == key && v == value }) != nil
  }

  static func == (lhs: FormBodyData, rhs: FormBodyData) -> Bool {
    for (lk, lv) in lhs.content {
      guard rhs.contains(key: lk, value: lv) else {
        return false
      }
    }
    return true
  }
}
