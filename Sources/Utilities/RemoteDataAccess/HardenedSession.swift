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

/// Library-owned `URLSession` with a hardened default for OpenID4VCI traffic:
///
/// - `URLSessionConfiguration.ephemeral`: no on-disk URL cache, no persistent cookie
///   storage. Prevents access tokens, pre-authorized codes, credential offers, and
///   session-correlating cookies from being written to the app sandbox.
/// - `SameOriginRedirectDelegate`: refuses HTTP redirects whose target is not the same
///   origin (scheme + host + port) as the original request. Prevents DPoP proofs, client
///   attestation JWTs, and 307/308-preserved request bodies from being forwarded to a
///   different host.
///
/// Callers that need a different policy can still inject their own `Networking` conformer.
public enum HardenedSession {

  /// The shared hardened session used as the default for every Fetcher/Poster in the
  /// library. Constructed once at program startup.
  public static let `default`: URLSession = makeSession()

  private static let delegate = SameOriginRedirectDelegate()

  private static func makeSession() -> URLSession {
    URLSession(
      configuration: .ephemeral,
      delegate: delegate,
      delegateQueue: nil
    )
  }
}

/// URLSession delegate that refuses any HTTP redirect to a different origin. Callers that
/// want the redirect must reissue the request themselves after inspecting the response.
final class SameOriginRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse,
    newRequest request: URLRequest,
    completionHandler: @escaping (URLRequest?) -> Void
  ) {
    guard let originalURL = task.originalRequest?.url,
          let targetURL = request.url,
          Self.sameOrigin(originalURL, targetURL) else {
      completionHandler(nil)
      return
    }
    completionHandler(request)
  }

  static func sameOrigin(_ lhs: URL, _ rhs: URL) -> Bool {
    guard let lhsScheme = lhs.scheme?.lowercased(),
          let rhsScheme = rhs.scheme?.lowercased(),
          lhsScheme == rhsScheme,
          let lhsHost = lhs.host?.lowercased(),
          let rhsHost = rhs.host?.lowercased(),
          lhsHost == rhsHost else {
      return false
    }
    return normalizedPort(for: lhs) == normalizedPort(for: rhs)
  }

  private static func normalizedPort(for url: URL) -> Int? {
    if let port = url.port { return port }
    switch url.scheme?.lowercased() {
    case "https": return 443
    case "http": return 80
    default: return nil
    }
  }
}
