use crowsi_credential_authority_contracts::EndpointRevocationExecutionReservationV1;
use ihat_identity_assertion_contracts::AuthorityRequestV1;

use crate::{
    AgentError,
    replay::DurableSecurityState,
    source_approve_state_types::{
        SourceApprovePhaseV1 as P, SourceApproveResume, SourceReservationTrustPinV1,
    },
    source_options_state,
};

pub(super) fn accepted(
    state: &DurableSecurityState,
    operation: &str,
    response_wire: &[u8],
    response: &EndpointRevocationExecutionReservationV1,
    trust: SourceReservationTrustPinV1,
    final_request: &AuthorityRequestV1,
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
        if record.phase != P::ExecutionReserveUnknown {
            return Err(AgentError::OperationReplay);
        }
        record.execution_reservation_json = Some(response_json);
        record.execution_reservation = Some(response.clone());
        record.execution_reservation_trust = Some(trust);
        record.revocation_final_request = Some(final_request.clone());
        record.phase = P::RevocationFinalPrepared;
        record.updated_at_epoch_s = now;
        record.expires_at_epoch_s = crate::source_approve_state::expiration(selected, record)?;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::source_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
