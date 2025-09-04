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
import zlib

public protocol DataDecompressing {
  func decompress(_ data: Data) async throws -> Data
  func decompress(_ string: String) async throws -> String
}

// MARK: - Errors

public enum DecompressionError: Error {
  case emptyInput
  case inflateInit(code: Int32)
  case inflate(code: Int32)
  case dataCorrupted
  case stringDecodingFailed
  case stringToDataFailed
}

// MARK: - Implementation

/// DEFLATE ("DEF") decompressor
/// Tries raw DEFLATE first (no zlib/gzip headers), then zlib/gzip as a fallback.
public actor DeflateDecompressor: DataDecompressing {
  
  public init() {}
  
  // Data -> Data
  public func decompress(_ data: Data) throws -> Data {
    guard !data.isEmpty else { throw DecompressionError.emptyInput }
    
    if let out = try? inflate(data, windowBits: -MAX_WBITS) { // raw DEFLATE
      return out
    }
    // Fallback: auto-detect zlib or gzip
    return try inflate(data, windowBits: MAX_WBITS + 32)
  }
  
  // Base64 String -> String (UTF-8 by default)
  public func decompress(_ string: String) throws -> String {
    guard let compressedData = Data(base64Encoded: string) else {
      throw DecompressionError.stringToDataFailed
    }
    let bytes = try decompress(compressedData)
    guard let decoded = String(data: bytes, encoding: .utf8) else {
      throw DecompressionError.stringDecodingFailed
    }
    return decoded
  }
  
  private func inflate(_ compressed: Data, windowBits: Int32) throws -> Data {
    var stream = z_stream()
    var status = inflateInit2_(&stream, windowBits, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
    guard status == Z_OK else { throw DecompressionError.inflateInit(code: status) }
    defer { inflateEnd(&stream) }
    
    var output = Data()
    let chunkSize = 64 * 1024
    
    try compressed.withUnsafeBytes { (rawPtr: UnsafeRawBufferPointer) in
      guard let base = rawPtr.bindMemory(to: Bytef.self).baseAddress else {
        throw DecompressionError.dataCorrupted
      }
      stream.next_in = UnsafeMutablePointer<Bytef>(mutating: base)
      stream.avail_in = uInt(compressed.count)
      
      while true {
        var chunk = Data(count: chunkSize)
        let wrote: Int = try chunk.withUnsafeMutableBytes { outPtr -> Int in
          guard let outBase = outPtr.bindMemory(to: Bytef.self).baseAddress else {
            throw DecompressionError.dataCorrupted
          }
          stream.next_out = outBase
          stream.avail_out = uInt(chunkSize)
          
          status = zlib.inflate(&stream, Z_NO_FLUSH)
          switch status {
          case Z_STREAM_END, Z_OK:
            return chunkSize - Int(stream.avail_out)
          default:
            throw DecompressionError.inflate(code: status)
          }
        }
        
        if wrote > 0 {
          output.append(chunk.prefix(wrote))
        }
        
        if status == Z_STREAM_END { break }
        if stream.avail_in == 0 && wrote == 0 { throw DecompressionError.dataCorrupted }
      }
    }
    
    return output
  }
}


