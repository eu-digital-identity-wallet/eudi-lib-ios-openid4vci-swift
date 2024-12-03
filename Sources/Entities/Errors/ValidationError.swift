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

public enum ValidationError: Error, LocalizedError {
  case error(reason: String)
  case todo(reason: String)
  case nonHttpsUrl(String)
  case invalidUrl(String)
  case response(GenericErrorResponse)
  case invalidBatchSize(Int)
  case issuerBatchSizeLimitExceeded(Int)
  case retryFailedAfterDpopNonce
  
  public var errorDescription: String? {
    switch self {
    case .error(let reason):
      return "ValidationError:error: \(reason)"
    case .todo(let reason):
      return "ValidationError:todo: \(reason)"
    case .nonHttpsUrl(let url):
      return "ValidationError:nonHttpsUrl: \(url)"
    case .invalidUrl(let url):
      return "ValidationError:invalidUrl: \(url)"
    case .response(let response):
      return "ValidationError:response: \(response.errorDescription ?? "")"
    case .invalidBatchSize(let size):
      return "ValidationError:invalidBatchSize: \(size)"
    case .issuerBatchSizeLimitExceeded(let size):
      return "ValidationError:issuerBatchSizeLimitExceeded: \(size)"
    case .retryFailedAfterDpopNonce:
      return "retryFailedAfterDpopNonce"
    }
  }
}
