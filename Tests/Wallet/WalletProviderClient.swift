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

/// Errors returned by `WalletProviderClient`
public enum WalletProviderError: Error, LocalizedError {
  case invalidURL
  case http(status: Int, body: Data?)
  case decoding(Error)
  case encoding(Error)
  case transport(Error)
  case unexpectedResponse
  
  public var errorDescription: String? {
    switch self {
    case .invalidURL: return "Invalid URL."
    case .http(let status, _): return "HTTP error \(status)."
    case .decoding(let err): return "Decoding error: \(err.localizedDescription)"
    case .encoding(let err): return "Encoding error: \(err.localizedDescription)"
    case .transport(let err): return "Transport error: \(err.localizedDescription)"
    case .unexpectedResponse: return "Unexpected response shape."
    }
  }
}

/// A very forgiving model for `/challenge` results.
///
/// Known implementations typically return `{ "challenge": "<string>", "expiresAt": "<ISO8601-date>?" }`.
/// This decoder will also accept `{ "nonce": "<string>" }` or a plain string body if the service ever returns that.
public struct ChallengeResponse: Decodable {
  public let challenge: String
  public let expiresAt: Date?
  
  public init(challenge: String, expiresAt: Date? = nil) {
    self.challenge = challenge
    self.expiresAt = expiresAt
  }
  
  public init(from decoder: Decoder) throws {
    // try object first
    let container = try? decoder.container(keyedBy: CodingKeys.self)
    if let c = container {
      // Accept multiple possible keys for the challenge field
      if let value = try? c.decode(String.self, forKey: .challenge) {
        self.challenge = value
      } else if let value = try? c.decode(String.self, forKey: .nonce) {
        self.challenge = value
      } else {
        throw DecodingError.keyNotFound(CodingKeys.challenge, .init(codingPath: c.codingPath, debugDescription: "Missing challenge/nonce"))
      }
      // Expiry is optional
      self.expiresAt = try? c.decode(Date.self, forKey: .expiresAt)
      return
    }
    // fall back: if the API ever returns a bare string
    let single = try? decoder.singleValueContainer()
    if let s = try? single?.decode(String.self) {
      self.challenge = s
      self.expiresAt = nil
      return
    }
    throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Unsupported challenge response"))
  }
  
  enum CodingKeys: String, CodingKey {
    case challenge
    case nonce
    case expiresAt
  }
}

public struct WalletInstanceAttestation: Decodable {
  public let walletInstanceAttestation: String
  
  public init(walletInstanceAttestation: String) {
    self.walletInstanceAttestation = walletInstanceAttestation
  }
}

public struct WalletUnitAttestation: Sendable, Decodable {
  public let walletUnitAttestation: String
  
  public init(walletUnitAttestation: String) {
    self.walletUnitAttestation = walletUnitAttestation
  }
}

/// Minimal Swift client for the Wallet Provider dev API.
/// - Only implements `/challenge` and `/wallet-instance-attestation/jwk`.
///
/// Usage:
/// ```swift
/// let client = WalletProviderClient(baseURL: URL(string: "https://dev.wallet-provider.eudiw.dev")!)
/// let chal = try await client.getChallenge()
/// let att = try await client.issueWalletApplicationAttestation(jwk: jwk) // jwk is JOSESwift JWK
/// print(att.jwt)
/// ```
public final class WalletProviderClient {
  public struct Config {
    public var baseURL: URL
    public var additionalHeaders: [String: String] = [:]
    public var timeout: TimeInterval = 30
    
    public init(baseURL: URL, additionalHeaders: [String: String] = [:], timeout: TimeInterval = 30) {
      self.baseURL = baseURL
      self.additionalHeaders = additionalHeaders
      self.timeout = timeout
    }
  }
  
  private let session: URLSession
  private let config: Config
  
  public init(config: Config, session: URLSession? = nil) {
    self.config = config
    if let s = session {
      self.session = s
    } else {
      let cfg = URLSessionConfiguration.ephemeral
      cfg.timeoutIntervalForRequest = config.timeout
      cfg.httpAdditionalHeaders = ["Accept": "application/json", "Content-Type": "application/json"]
      // Merge any custom headers
      for (k, v) in config.additionalHeaders {
        cfg.httpAdditionalHeaders?[k] = v
      }
      self.session = URLSession(configuration: cfg)
    }
  }
  
  public convenience init(baseURL: URL) {
    self.init(config: .init(baseURL: baseURL))
  }
  
  // MARK: - Public API
  
  /// GET /challenge
  @discardableResult
  public func getChallenge() async throws -> ChallengeResponse {
    let url = config.baseURL.appendingPathComponent("challenge")
    var req = URLRequest(url: url)
    req.httpMethod = "POST"
    return try await send(req, decode: ChallengeResponse.self)
  }
  
  /// POST /wallet-instance-attestation/jwk
  ///
  /// The body is the JWK dictionary provided by your JOSESwift `JWK.toDictionary()`.
  ///
  /// - Parameter jwkDictionary: e.g. from `myJWK.toDictionary()`
  /// - Returns: a decoded `WalletApplicationAttestation` with the `jwt` string
  @discardableResult
  public func issueWalletInstanceAttestation(payload dictionary: [String: Any]) async throws -> WalletInstanceAttestation {
    let url = config.baseURL
      .appendingPathComponent("wallet-instance-attestation")
      .appendingPathComponent("jwk")
    var req = URLRequest(url: url)
    req.httpMethod = "POST"
    req.allHTTPHeaderFields = [
      "Content-Type": "application/json",
      "Accept": "application/json"
    ]
    do {
      req.httpBody = try JSONSerialization.data(withJSONObject: dictionary, options: [])
    } catch {
      throw WalletProviderError.encoding(error)
    }
    return try await send(req, decode: WalletInstanceAttestation.self)
  }
  
  /// POST /wallet-unit-attestation/jwk-set
  ///
  /// The body is a JWKS dictionary (`{ "keys": [ ... ] }`) built from your key set.
  /// - Parameter dictionary: a JSON-serializable JWKS (e.g., from your library) and nonce
  /// - Returns: a decoded `WalletUnitAttestation` with the attestation JWT
  @discardableResult
  public func issueWalletUnitAttestation(dictionary: [String: Any]) async throws -> WalletUnitAttestation {
    let url = config.baseURL
      .appendingPathComponent("wallet-unit-attestation")
      .appendingPathComponent("jwk-set")
    var req = URLRequest(url: url)
    req.httpMethod = "POST"
    req.allHTTPHeaderFields = [
      "Content-Type": "application/json",
      "Accept": "application/json"
    ]
    do {
      req.httpBody = try JSONSerialization.data(withJSONObject: dictionary, options: [])
    } catch {
      throw WalletProviderError.encoding(error)
    }
    return try await send(req, decode: WalletUnitAttestation.self)
  }
  
  // MARK: - Internals
  
  private func send<T: Decodable>(_ request: URLRequest, decode: T.Type) async throws -> T {
    do {
      let (data, resp) = try await session.data(for: request)
      guard let http = resp as? HTTPURLResponse else {
        throw WalletProviderError.unexpectedResponse
      }
      guard (200..<300).contains(http.statusCode) else {
        return try handleHTTPError(status: http.statusCode, data: data)
      }
      do {
        // decode with ISO8601 allowance (for potential expiresAt)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(T.self, from: data)
      } catch {
        // If decoding fails and T == Data or String, try graceful fallback
        if T.self == Data.self, let cast = data as? T {
          return cast
        }
        if T.self == String.self, let s = String(data: data, encoding: .utf8) as? T {
          return s
        }
        throw WalletProviderError.decoding(error)
      }
    } catch {
      // URLSession/transport-level error
      throw WalletProviderError.transport(error)
    }
  }
  
  private func handleHTTPError<T>(status: Int, data: Data?) throws -> T {
    // Optionally parse backend error JSON here. For now, just bubble up.
    throw WalletProviderError.http(status: status, body: data)
  }
}

