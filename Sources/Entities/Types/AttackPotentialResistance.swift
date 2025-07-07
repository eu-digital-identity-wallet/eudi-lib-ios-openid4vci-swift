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

/// Represents the resistance level of key storage or user authentication
/// against attacks, as defined in ISO/IEC 18045.
public enum AttackPotentialResistance: String {
  
  /// Resistant to attack with attack potential "High", equivalent to VAN.5.
  case iso18045High = "iso_18045_high"
  
  /// Resistant to attack with attack potential "Moderate", equivalent to VAN.4.
  case iso18045Moderate = "iso_18045_moderate"
  
  /// Resistant to attack with attack potential "Enhanced-Basic", equivalent to VAN.3.
  case iso18045EnhancedBasic = "iso_18045_enhanced-basic"
  
  /// Resistant to attack with attack potential "Basic", equivalent to VAN.2.
  case iso18045Basic = "iso_18045_basic"
}


