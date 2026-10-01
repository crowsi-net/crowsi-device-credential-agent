use crowsi_credential_authority_contracts::ManagementRequestV2;
use ihat_identity_assertion_contracts::AuthorityRequestV1;

use crate::source_approve_state_types::{SourceApprovePhaseV1, SourceApproveRecordV1};

pub(super) fn initial(
    operation_id: &str,
    browser: &ManagementRequestV2,
    digest: String,
    finish_request: &AuthorityRequestV1,
    expires: u64,
    now: u64,
) -> SourceApproveRecordV1 {
    SourceApproveRecordV1 {
        operation_id: operation_id.to_owned(),
        browser_request: browser.clone(),
        browser_request_digest_sha256: digest,
        phase: SourceApprovePhaseV1::FinishPrepared,
        finish_request: finish_request.clone(),
        finish_exchange: None,
        current_request: None,
        current_exchange: None,
        current_observed_at_epoch_s: None,
        revocation_begin_request: None,
        revocation_begin_exchange: None,
        revocation_response_key_id: None,
        revocation_response_public_key_hex: None,
        revocation_response_minimum_generation: None,
        revocation_final_request: None,
        revocation_final_exchange: None,
        pre_final_response_json: None,
        pre_final_response: None,
        revocation_finalize_request_id: None,
        reservation_current_request: None,
        reservation_current_exchange: None,
        reservation_current_observed_at_epoch_s: None,
        execution_reserve_request_json: None,
        execution_reserve_request: None,
        execution_reservation_json: None,
        execution_reservation: None,
        execution_reservation_trust: None,
        revocation_finalize_request_json: None,
        revocation_finalize_request: None,
        central_envelope_json: None,
        central_envelope: None,
        response_json: None,
        response: None,
        expires_at_epoch_s: expires,
        updated_at_epoch_s: now,
    }
}
