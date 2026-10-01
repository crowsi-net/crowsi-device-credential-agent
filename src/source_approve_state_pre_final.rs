use crowsi_credential_authority_contracts::ManagementProjectionV2;
use ihat_identity_assertion_contracts::AuthorityRequestV1;

use crate::{
    AgentError,
    replay::DurableSecurityState,
    source_approve_state_types::{SourceApprovePhaseV1, SourceApproveResume},
    source_options_state,
};

pub(crate) fn accepted(
    state: &DurableSecurityState,
    operation: &str,
    response_wire: &[u8],
    response: &ManagementProjectionV2,
    finalize_request_id: &str,
    reservation_current_request: &AuthorityRequestV1,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
    if response_wire.len() > source_options_state::MAXIMUM_PHASE_WIRE_BYTES {
        return Err(AgentError::ResponseInvalid);
    }
    let response_json = std::str::from_utf8(response_wire)
        .map_err(|_| AgentError::ResponseInvalid)?
        .to_owned();
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let selected = fresh
            .records
            .get(operation)
            .and_then(|value| value.exchange.as_ref())
            .ok_or(AgentError::AuthorityRollback)?;
        let record = journal
            .source_approvals
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if record.phase == SourceApprovePhaseV1::ReservationCurrentPrepared {
            let same = record.pre_final_response.as_ref() == Some(response)
                && record.pre_final_response_json.as_deref() == Some(&response_json)
                && record.revocation_finalize_request_id.as_deref() == Some(finalize_request_id)
                && record.reservation_current_request.as_ref() == Some(reservation_current_request);
            if same {
                return unchanged(operation, &prepared, &fresh, &journal);
            }
            return Err(AgentError::AuthorityRollback);
        }
        if record.phase != SourceApprovePhaseV1::Unknown
            || record.revocation_final_request.is_none()
            || record.revocation_final_exchange.is_some()
            || !crate::source_approve_state_finalization::empty(record)
        {
            return Err(AgentError::OperationReplay);
        }
        record.pre_final_response_json = Some(response_json);
        record.pre_final_response = Some(response.clone());
        record.revocation_finalize_request_id = Some(finalize_request_id.into());
        record.reservation_current_request = Some(reservation_current_request.clone());
        record.phase = SourceApprovePhaseV1::ReservationCurrentPrepared;
        record.updated_at_epoch_s = now;
        record.expires_at_epoch_s = crate::source_approve_state::expiration(selected, record)?;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::source_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        crate::management_state::observe_in_transaction(values, response)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}

fn unchanged(
    operation: &str,
    prepared: &crate::source_options_state_types::PreparedOperationsV1,
    fresh: &crate::source_options_state_types::FreshUvAttemptsV1,
    journal: &crate::source_options_state_types::OperationJournalV1,
) -> Result<(SourceApproveResume, bool), AgentError> {
    Ok((
        crate::source_approve_state::resume(operation, prepared, fresh, journal)?,
        false,
    ))
}
