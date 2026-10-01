use crowsi_credential_authority_contracts::{
    EndpointIndependentRevocationPreFinalProjectionHistoricTrustV1,
    EndpointRevocationExecutionReservationHistoricTrustV1,
    decode_endpoint_independent_revocation_finalize_request_strict,
    decode_endpoint_independent_revocation_pre_final_request_strict,
    decode_endpoint_revocation_execution_reservation_strict,
    decode_endpoint_revocation_execution_reserve_request_strict,
    decode_management_projection_strict,
    validate_endpoint_independent_revocation_finalize_against_acceptance,
    verify_endpoint_independent_revocation_pre_final_projection_historic,
    verify_endpoint_revocation_execution_reservation_historic,
};

use crate::{AgentError, independent_approve_state_types::IndependentApproveResume};

pub(super) fn exact(value: &IndependentApproveResume) -> Result<(), AgentError> {
    let pre_final = pre_final_request(value)?;
    pre_final_response(value, pre_final.as_ref())?;
    let reserve = reserve_request(value)?;
    reservation(value, reserve.as_ref())?;
    finalize(value, pre_final.as_ref(), reserve.as_ref())?;
    response(value)
}

fn pre_final_request(
    value: &IndependentApproveResume,
) -> Result<
    Option<crowsi_credential_authority_contracts::EndpointIndependentRevocationPreFinalRequestV1>,
    AgentError,
> {
    decode_pair(
        value.approval.pre_final_request_json.as_deref(),
        value.approval.pre_final_request.as_ref(),
        decode_endpoint_independent_revocation_pre_final_request_strict,
    )
}

fn reserve_request(
    value: &IndependentApproveResume,
) -> Result<
    Option<crowsi_credential_authority_contracts::EndpointRevocationExecutionReserveRequestV1>,
    AgentError,
> {
    decode_pair(
        value.approval.execution_reserve_request_json.as_deref(),
        value.approval.execution_reserve_request.as_ref(),
        decode_endpoint_revocation_execution_reserve_request_strict,
    )
}

include!("independent_approve_state_wire_central_verify.rs");
