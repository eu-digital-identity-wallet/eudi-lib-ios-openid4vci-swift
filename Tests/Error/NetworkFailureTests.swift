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

/// Networking stub that always answers with the given status code and body.
private struct StatusNetworking: Networking {
  let statusCode: Int
  let body: Data

  init(statusCode: Int, body: String = "{\"error\":\"unauthorized\"}") {
    self.statusCode = statusCode
    self.body = Data(body.utf8)
  }

  func data(from url: URL) async throws -> (Data, URLResponse) {
    let response = HTTPURLResponse(url: url, statusCode: statusCode, httpVersion: nil, headerFields: nil)!
    return (body, response)
  }

  func data(for request: URLRequest) async throws -> (Data, URLResponse) {
    try await data(from: request.url!)
  }
}

/// Networking stub that never gets a response.
private struct TransportFailureNetworking: Networking {
  let code: URLError.Code

  func data(from url: URL) async throws -> (Data, URLResponse) {
    throw URLError(code)
  }

  func data(for request: URLRequest) async throws -> (Data, URLResponse) {
    throw URLError(code)
  }
}

final class NetworkFailureTests: XCTestCase {

  private let url = URL(string: "https://issuer.example/credential-offer/abc")!
  private let issuerBody = "{\"error\":\"unauthorized\"}"
  private let issuerWellKnownURL = URL(string: "https://credential-issuer.example.com/.well-known/openid-credential-issuer")!

  // MARK: - Fetcher

  func testFetch_WhenNon2xx_ReturnsInvalidStatusCodeNotDecodingError() async {
    let fetcher = Fetcher<[String: String]>(session: StatusNetworking(statusCode: 429))

    let result = await fetcher.fetch(url: url)

    guard case .failure(.invalidStatusCode(let failedUrl, let code, let body)) = result else {
      return XCTFail("Expected invalidStatusCode, got \(result)")
    }
    XCTAssertEqual(failedUrl, url)
    XCTAssertEqual(code, 429)
    XCTAssertEqual(body.map { String(decoding: $0, as: UTF8.self) }, issuerBody)
  }

  func testFetch_WhenTransportFails_ReturnsNetworkErrorWithURLError() async {
    let fetcher = Fetcher<[String: String]>(session: TransportFailureNetworking(code: .timedOut))

    let result = await fetcher.fetch(url: url)

    guard case .failure(.networkError(let underlying)) = result else {
      return XCTFail("Expected networkError, got \(result)")
    }
    XCTAssertEqual((underlying as? URLError)?.code, .timedOut)
  }

  func testFetchString_WhenNon2xx_ThrowsInvalidStatusCodeWithBody() async {
    let fetcher = Fetcher<String>(session: StatusNetworking(statusCode: 401))

    do {
      _ = try await fetcher.fetchString(url: url)
      XCTFail("Expected FetchError")
    } catch FetchError.invalidStatusCode(let failedUrl, let code, let body) {
      XCTAssertEqual(failedUrl, url)
      XCTAssertEqual(code, 401)
      XCTAssertEqual(body.map { String(decoding: $0, as: UTF8.self) }, issuerBody)
    } catch {
      XCTFail("Expected invalidStatusCode, got \(error)")
    }
  }

  func testFetchString_WhenTransportFails_ThrowsNetworkErrorWithURLError() async {
    let fetcher = Fetcher<String>(session: TransportFailureNetworking(code: .timedOut))

    do {
      _ = try await fetcher.fetchString(url: url)
      XCTFail("Expected FetchError")
    } catch FetchError.networkError(let underlying) {
      XCTAssertEqual((underlying as? URLError)?.code, .timedOut)
    } catch {
      XCTFail("Expected networkError, got \(error)")
    }
  }

  func testFetchError_InvalidStatusCodeDescription_ContainsCodeAndUrl() {
    let error = FetchError.invalidStatusCode(url, 404, nil)
    XCTAssertEqual(error.errorDescription, ".invalidStatusCode 404 \(url)")
  }

  // MARK: - RawDataFetcher

  func testFetchRaw_WhenNon2xx_ReturnsInvalidStatusCodeNotNetworkError() async {
    let fetcher = RawDataFetcher(session: StatusNetworking(statusCode: 429))

    let result = await fetcher.fetchRawWithHeaders(url: url, additionalHeaders: [:])

    guard case .failure(.invalidStatusCode(let failedUrl, let code, let body)) = result else {
      return XCTFail("Expected invalidStatusCode, got \(result)")
    }
    XCTAssertEqual(failedUrl, url)
    XCTAssertEqual(code, 429)
    XCTAssertEqual(body.map { String(decoding: $0, as: UTF8.self) }, issuerBody)
  }

  func testFetchRaw_WhenTransportFails_ReturnsNetworkErrorWithURLError() async {
    let fetcher = RawDataFetcher(session: TransportFailureNetworking(code: .notConnectedToInternet))

    let result = await fetcher.fetchRawWithHeaders(url: url, additionalHeaders: [:])

    guard case .failure(.networkError(let underlying)) = result else {
      return XCTFail("Expected networkError, got \(result)")
    }
    XCTAssertEqual((underlying as? URLError)?.code, .notConnectedToInternet)
  }

  // MARK: - Poster

  func testPost_When5xx_ReturnsInvalidStatusCodeWithBody() async {
    let poster = Poster(session: StatusNetworking(statusCode: 503))

    let result: Result<ResponseWithHeaders<[String: String]>, Error> = await poster.post(request: URLRequest(url: url))

    guard case .failure(PostError.invalidStatusCode(let failedUrl, let code, let body)) = result else {
      return XCTFail("Expected invalidStatusCode, got \(result)")
    }
    XCTAssertEqual(failedUrl, url)
    XCTAssertEqual(code, 503)
    XCTAssertEqual(body.map { String(decoding: $0, as: UTF8.self) }, issuerBody)
  }

  func testPost_WhenTransportFails_ReturnsNetworkError() async {
    let poster = Poster(session: TransportFailureNetworking(code: .timedOut))

    let result: Result<ResponseWithHeaders<[String: String]>, Error> = await poster.post(request: URLRequest(url: url))

    guard case .failure(PostError.networkError(let underlying)) = result else {
      return XCTFail("Expected networkError, got \(result)")
    }
    XCTAssertEqual((underlying as? URLError)?.code, .timedOut)
  }

  // MARK: - NetworkFailure

  func testNetworkFailure_FromFetchInvalidStatusCode_KeepsStatusBodyAndFailedUrl() {
    let failedUrl = URL(string: "https://issuer.example/other")!
    let body = Data("busy".utf8)

    let failure = NetworkFailure(stage: .GET, url: url, fetchError: .invalidStatusCode(failedUrl, 429, body))

    XCTAssertEqual(failure.stage, .GET)
    XCTAssertEqual(failure.url, failedUrl)
    XCTAssertEqual(failure.statusCode, 429)
    XCTAssertEqual(failure.responseBody, body)
    XCTAssertTrue(failure.isServerResponse)
    XCTAssertNil(failure.urlError)
  }

  func testNetworkFailure_FromFetchNetworkError_ExposesURLError() {
    let failure = NetworkFailure(stage: .GET, url: url, fetchError: .networkError(URLError(.timedOut)))

    XCTAssertEqual(failure.url, url)
    XCTAssertNil(failure.statusCode)
    XCTAssertFalse(failure.isServerResponse)
    XCTAssertEqual(failure.urlError?.code, .timedOut)
  }

  func testNetworkFailure_FromPostRequestError_KeepsStatusAndUnderlying() {
    let decoding = NSError(domain: "decoding", code: 7)

    let failure = NetworkFailure(stage: .POST, url: url, postError: .requestError(429, decoding))

    XCTAssertEqual(failure.stage, .POST)
    XCTAssertEqual(failure.statusCode, 429)
    XCTAssertEqual((failure.underlying as? NSError)?.domain, "decoding")
  }

  func testNetworkFailure_FromPostInvalidStatusCode_FallsBackToRequestUrl() {
    let failure = NetworkFailure(stage: .POST, url: url, postError: .invalidStatusCode(nil, 502, nil))

    XCTAssertEqual(failure.url, url)
    XCTAssertEqual(failure.statusCode, 502)
  }

  func testNetworkFailure_Equality_ComparesStageUrlStatusAndUnderlyingCode() {
    let lhs = NetworkFailure(stage: .GET, url: url, underlying: URLError(.timedOut))
    let rhs = NetworkFailure(stage: .GET, url: url, underlying: URLError(.timedOut))
    let other = NetworkFailure(stage: .GET, url: url, underlying: URLError(.cannotFindHost))

    XCTAssertEqual(lhs, rhs)
    XCTAssertNotEqual(lhs, other)
  }

  func testValidationError_NetworkErrorDescription_MentionsStageUrlAndCause() {
    let failure = NetworkFailure(stage: .GET, url: url, statusCode: 429)

    XCTAssertEqual(ValidationError.networkError(failure).errorDescription, ".networkError GET \(url): status 429")
  }

  // MARK: - CredentialOfferRequestResolver

  func testResolveOffer_WhenOfferByReferenceTimesOut_FailsWithNetworkError() async {
    let resolver = CredentialOfferRequestResolver(
      fetcher: Fetcher<CredentialOfferRequestObject>(session: TransportFailureNetworking(code: .timedOut)),
      credentialIssuerMetadataResolver: makeIssuerMetadataResolver(session: issuerMetadataSession()),
      authorizationServerMetadataResolver: makeAuthorizationServerResolver(
        oauth: StatusNetworking(statusCode: 404),
        oidc: oidcMetadataSession()
      )
    )

    let result = await resolver.resolve(source: .fetchByReference(url: .stub()), policy: .ignoreSigned)

    let failure = networkFailure(from: result)
    XCTAssertEqual(failure?.stage, .GET)
    XCTAssertEqual(failure?.url, .stub())
    XCTAssertEqual(failure?.urlError?.code, .timedOut)
  }

  func testResolveOffer_WhenIssuerMetadataIsRateLimited_FailsWithNetworkErrorCarryingStatus() async {
    let resolver = CredentialOfferRequestResolver(
      fetcher: offerFetcher(),
      credentialIssuerMetadataResolver: makeIssuerMetadataResolver(session: StatusNetworking(statusCode: 429)),
      authorizationServerMetadataResolver: makeAuthorizationServerResolver(
        oauth: StatusNetworking(statusCode: 404),
        oidc: oidcMetadataSession()
      )
    )

    let result = await resolver.resolve(source: .fetchByReference(url: .stub()), policy: .ignoreSigned)

    let failure = networkFailure(from: result)
    XCTAssertEqual(failure?.stage, .GET)
    XCTAssertEqual(failure?.url, issuerWellKnownURL)
    XCTAssertEqual(failure?.statusCode, 429)
    XCTAssertEqual(failure?.responseBody.map { String(decoding: $0, as: UTF8.self) }, issuerBody)
  }

  func testResolveOffer_WhenIssuerMetadataIsNotSigned_PassesMetadataErrorOn() async {
    let resolver = CredentialOfferRequestResolver(
      fetcher: offerFetcher(),
      credentialIssuerMetadataResolver: makeIssuerMetadataResolver(session: issuerMetadataSession()),
      authorizationServerMetadataResolver: makeAuthorizationServerResolver(
        oauth: StatusNetworking(statusCode: 404),
        oidc: oidcMetadataSession()
      )
    )

    let result = await resolver.resolve(
      source: .fetchByReference(url: .stub()),
      policy: .requireSigned(issuerTrust: .byCertificateChain(certificateChainTrust: TestTrust()))
    )

    guard case .failure(let error) = result else {
      return XCTFail("Expected failure, got \(result)")
    }
    XCTAssertTrue(error is CredentialIssuerMetadataError, "Expected CredentialIssuerMetadataError, got \(error)")
  }

  func testResolveOffer_WhenAuthorizationServerTimesOut_FailsWithNetworkError() async {
    let resolver = CredentialOfferRequestResolver(
      fetcher: offerFetcher(),
      credentialIssuerMetadataResolver: makeIssuerMetadataResolver(session: issuerMetadataSession()),
      authorizationServerMetadataResolver: makeAuthorizationServerResolver(
        oauth: StatusNetworking(statusCode: 404),
        oidc: TransportFailureNetworking(code: .timedOut)
      )
    )

    let result = await resolver.resolve(source: .fetchByReference(url: .stub()), policy: .ignoreSigned)

    let failure = networkFailure(from: result)
    XCTAssertEqual(failure?.stage, .GET)
    XCTAssertEqual(failure?.url?.pathComponents.contains("openid-configuration"), true)
    XCTAssertEqual(failure?.urlError?.code, .timedOut)
  }

  func testResolveOffer_WhenAuthorizationServerIsRateLimitedOnFirstFlavour_ReportsThatFailure() async {
    let resolver = CredentialOfferRequestResolver(
      fetcher: offerFetcher(),
      credentialIssuerMetadataResolver: makeIssuerMetadataResolver(session: issuerMetadataSession()),
      authorizationServerMetadataResolver: makeAuthorizationServerResolver(
        oauth: StatusNetworking(statusCode: 429),
        oidc: StatusNetworking(statusCode: 404)
      )
    )

    let result = await resolver.resolve(source: .fetchByReference(url: .stub()), policy: .ignoreSigned)

    let failure = networkFailure(from: result)
    XCTAssertEqual(failure?.url?.pathComponents.contains("oauth-authorization-server"), true)
    XCTAssertEqual(failure?.statusCode, 429)
  }

  func testResolveOffer_WhenNoDiscoveryFlavourExists_KeepsValidationError() async {
    let resolver = CredentialOfferRequestResolver(
      fetcher: offerFetcher(),
      credentialIssuerMetadataResolver: makeIssuerMetadataResolver(session: issuerMetadataSession()),
      authorizationServerMetadataResolver: makeAuthorizationServerResolver(
        oauth: StatusNetworking(statusCode: 404),
        oidc: StatusNetworking(statusCode: 404)
      )
    )

    let result = await resolver.resolve(source: .fetchByReference(url: .stub()), policy: .ignoreSigned)

    guard case .failure(ValidationError.error(let reason)) = result else {
      return XCTFail("Expected ValidationError.error, got \(result)")
    }
    XCTAssertEqual(reason, "Invalid authorization metadata")
  }

  // MARK: - Helpers

  private func networkFailure(from result: Result<CredentialOffer, Error>) -> NetworkFailure? {
    guard case .failure(ValidationError.networkError(let failure)) = result else {
      XCTFail("Expected ValidationError.networkError, got \(result)")
      return nil
    }
    return failure
  }

  private func offerFetcher() -> Fetcher<CredentialOfferRequestObject> {
    Fetcher(session: NetworkingMock(path: "credential_offer_with_blank_pre_authorized_code", extension: "json"))
  }

  private func issuerMetadataSession() -> Networking {
    NetworkingMock(path: "credential_issuer_metadata", extension: "json", headers: ["Content-Type": "application/json"])
  }

  private func oidcMetadataSession() -> Networking {
    NetworkingMock(path: "oidc_authorization_server_metadata", extension: "json")
  }

  private func makeIssuerMetadataResolver(session: Networking) -> CredentialIssuerMetadataResolver {
    CredentialIssuerMetadataResolver(fetcher: MetadataFetcher(rawFetcher: RawDataFetcher(session: session)))
  }

  private func makeAuthorizationServerResolver(oauth: Networking, oidc: Networking) -> AuthorizationServerMetadataResolver {
    AuthorizationServerMetadataResolver(
      oidcFetcher: Fetcher<OIDCProviderMetadata>(session: oidc),
      oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: oauth)
    )
  }
}
