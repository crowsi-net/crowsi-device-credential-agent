use crowsi_credential_authority_contracts::EndpointRevocationExecutionReservationV1;
use ihat_identity_assertion_contracts::AuthorityRequestV1;

use crate::{
    AgentError,
    independent_approve_state_types::{
        IndependentApprovePhaseV1 as P, IndependentApproveResume, IndependentReservationTrustPinV1,
    },
    replay::DurableSecurityState,
};

pub(super) fn accepted(
    state: &DurableSecurityState,
    operation: &str,
    response_wire: &[u8],
    response: &EndpointRevocationExecutionReservationV1,
    trust: IndependentReservationTrustPinV1,
    final_request: &AuthorityRequestV1,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    if response_wire.len() > crate::source_options_state::MAXIMUM_PHASE_WIRE_BYTES {
        return Err(AgentError::ResponseInvalid);
    }
    let response_json = std::str::from_utf8(response_wire)
        .map_err(|_| AgentError::ResponseInvalid)?
        .to_owned();
    let final_json =
        serde_json::to_string(final_request).map_err(|_| AgentError::RequestInvalid)?;
    crate::independent_approve_state_update::apply(state, operation, now, |record| {
        if record.phase != P::ExecutionReserveUnknown {
            return Err(AgentError::OperationReplay);
        }
        record.execution_reservation_json = Some(response_json.clone());
        record.execution_reservation = Some(response.clone());
        record.execution_reservation_trust = Some(trust.clone());
        record.final_request_json = Some(final_json.clone());
        record.final_request = Some(final_request.clone());
        record.phase = P::FinalPrepared;
        Ok(())
    })
}
