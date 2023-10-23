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

public struct OIDCProviderMetadata: Codable, Equatable {
  public let acrValuesSupported: String?
  public let subjectTypesSupported: String?
  public let idTokenSigningAlgValuesSupported: String?
  public let idTokenEncryptionAlgValuesSupported: String?
  public let idTokenEncryptionEncValuesSupported: String?
  public let userinfoSigningAlgValuesSupported: String?
  public let userinfoEncryptionAlgValuesSupported: String?
  public let userinfoEncryptionEncValuesSupported: String?
  public let displayValuesSupported: String?
  public let claimTypesSupported: String?
  public let claimsSupported: String?
  public let claimsLocalesSupported: String?
  public let claimsParameterSupported: String?
  public let backchannelLogoutSupported: String?
  public let backchannelLogoutSessionSupported: String?
  public let frontchannelLogoutSupported: String?
  public let frontchannelLogoutSessionSupported: String?
  public let verifiedClaimsSupported: String?
  public let trustFrameworksSupported: String?
  public let evidenceSupported: String?
  public let documentsSupported: String?
  public let documentsMethodsSupported: String?
  public let documentsValidationMethodsSupported: String?
  public let documentsVerificationMethodsSupported: String?
  public let idDocumentsSupported: String? // deprecated
  public let idDocumentsVerificationMethodsSupported: String? // deprecated
  public let electronicRecordsSupported: String?
  public let claimsInVerifiedClaimsSupported: String?
  public let attachmentsSupported: String?
  public let digestAlgorithmsSupported: String?
  
  // CodingKeys for underscore case
  enum CodingKeys: String, CodingKey {
    case acrValuesSupported = "acr_values_supported"
    case subjectTypesSupported = "subject_types_supported"
    case idTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported"
    case idTokenEncryptionAlgValuesSupported = "id_token_encryption_alg_values_supported"
    case idTokenEncryptionEncValuesSupported = "id_token_encryption_enc_values_supported"
    case userinfoSigningAlgValuesSupported = "userinfo_signing_alg_values_supported"
    case userinfoEncryptionAlgValuesSupported = "userinfo_encryption_alg_values_supported"
    case userinfoEncryptionEncValuesSupported = "userinfo_encryption_enc_values_supported"
    case displayValuesSupported = "display_values_supported"
    case claimTypesSupported = "claim_types_supported"
    case claimsSupported = "claims_supported"
    case claimsLocalesSupported = "claims_locales_supported"
    case claimsParameterSupported = "claims_parameter_supported"
    case backchannelLogoutSupported = "backchannel_logout_supported"
    case backchannelLogoutSessionSupported = "backchannel_logout_session_supported"
    case frontchannelLogoutSupported = "frontchannel_logout_supported"
    case frontchannelLogoutSessionSupported = "frontchannel_logout_session_supported"
    case verifiedClaimsSupported = "verified_claims_supported"
    case trustFrameworksSupported = "trust_frameworks_supported"
    case evidenceSupported = "evidence_supported"
    case documentsSupported = "documents_supported"
    case documentsMethodsSupported = "documents_methods_supported"
    case documentsValidationMethodsSupported = "documents_validation_methods_supported"
    case documentsVerificationMethodsSupported = "documents_verification_methods_supported"
    case idDocumentsSupported = "id_documents_supported" // deprecated
    case idDocumentsVerificationMethodsSupported = "id_documents_verification_methods_supported" // deprecated
    case electronicRecordsSupported = "electronic_records_supported"
    case claimsInVerifiedClaimsSupported = "claims_in_verified_claims_supported"
    case attachmentsSupported = "attachments_supported"
    case digestAlgorithmsSupported = "digest_algorithms_supported"
  }
  
  public init(acrValuesSupported: String?, subjectTypesSupported: String?, idTokenSigningAlgValuesSupported: String?, idTokenEncryptionAlgValuesSupported: String?, idTokenEncryptionEncValuesSupported: String?, userinfoSigningAlgValuesSupported: String?, userinfoEncryptionAlgValuesSupported: String?, userinfoEncryptionEncValuesSupported: String?, displayValuesSupported: String?, claimTypesSupported: String?, claimsSupported: String?, claimsLocalesSupported: String?, claimsParameterSupported: String?, backchannelLogoutSupported: String?, backchannelLogoutSessionSupported: String?, frontchannelLogoutSupported: String?, frontchannelLogoutSessionSupported: String?, verifiedClaimsSupported: String?, trustFrameworksSupported: String?, evidenceSupported: String?, documentsSupported: String?, documentsMethodsSupported: String?, documentsValidationMethodsSupported: String?, documentsVerificationMethodsSupported: String?, idDocumentsSupported: String?, idDocumentsVerificationMethodsSupported: String?, electronicRecordsSupported: String?, claimsInVerifiedClaimsSupported: String?, attachmentsSupported: String?, digestAlgorithmsSupported: String?) {
    self.acrValuesSupported = acrValuesSupported
    self.subjectTypesSupported = subjectTypesSupported
    self.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported
    self.idTokenEncryptionAlgValuesSupported = idTokenEncryptionAlgValuesSupported
    self.idTokenEncryptionEncValuesSupported = idTokenEncryptionEncValuesSupported
    self.userinfoSigningAlgValuesSupported = userinfoSigningAlgValuesSupported
    self.userinfoEncryptionAlgValuesSupported = userinfoEncryptionAlgValuesSupported
    self.userinfoEncryptionEncValuesSupported = userinfoEncryptionEncValuesSupported
    self.displayValuesSupported = displayValuesSupported
    self.claimTypesSupported = claimTypesSupported
    self.claimsSupported = claimsSupported
    self.claimsLocalesSupported = claimsLocalesSupported
    self.claimsParameterSupported = claimsParameterSupported
    self.backchannelLogoutSupported = backchannelLogoutSupported
    self.backchannelLogoutSessionSupported = backchannelLogoutSessionSupported
    self.frontchannelLogoutSupported = frontchannelLogoutSupported
    self.frontchannelLogoutSessionSupported = frontchannelLogoutSessionSupported
    self.verifiedClaimsSupported = verifiedClaimsSupported
    self.trustFrameworksSupported = trustFrameworksSupported
    self.evidenceSupported = evidenceSupported
    self.documentsSupported = documentsSupported
    self.documentsMethodsSupported = documentsMethodsSupported
    self.documentsValidationMethodsSupported = documentsValidationMethodsSupported
    self.documentsVerificationMethodsSupported = documentsVerificationMethodsSupported
    self.idDocumentsSupported = idDocumentsSupported
    self.idDocumentsVerificationMethodsSupported = idDocumentsVerificationMethodsSupported
    self.electronicRecordsSupported = electronicRecordsSupported
    self.claimsInVerifiedClaimsSupported = claimsInVerifiedClaimsSupported
    self.attachmentsSupported = attachmentsSupported
    self.digestAlgorithmsSupported = digestAlgorithmsSupported
  }
}


