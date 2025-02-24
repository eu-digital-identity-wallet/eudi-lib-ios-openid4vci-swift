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

public struct Constants {
  public static let GRANT_TYPE_PARAM = "grant_type"
  public static let GRANT_TYPE_PARAM_VALUE = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
  
  public static let REDIRECT_URI_PARAM = "redirect_uri"
  public static let CLIENT_ID_PARAM = "client_id"
  public static let CODE_VERIFIER_PARAM = "code_verifier"
  public static let AUTHORIZATION_CODE_PARAM = "code"
  public static let AUTHORIZATION_DETAILS = "authorization_details"
  public static let USER_PIN_PARAM = "user_pin"
  public static let PRE_AUTHORIZED_CODE_PARAM = "pre-authorized_code"
  
  public static let OPENID_SCOPE = "openid"
  public static let TX_CODE_PARAM = "tx_code"
    
  public static let url = "https://a.bc"
  
  public static let DPOP_NONCE_HEADER = "dpop-nonce"
  public static let USE_DPOP_NONCE = "use_dpop_nonce"
  
  public static let REFRESH_TOKEN = "refresh_token"
  public static let REFRESH_TOKEN_PARAM = "refresh_token"
}
