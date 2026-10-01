use ihat_identity_assertion_contracts::{AuthorityRequestV1, decode_authority_request_strict};

use crate::{AgentError, independent_approve_state_types::IndependentApproveResume};

pub(super) fn exact(value: &IndependentApproveResume) -> Result<(), AgentError> {
    current(
        value.approval.current_request.as_ref(),
        value.approval.current_exchange.as_ref(),
    )?;
    current(
        value.approval.reservation_current_request.as_ref(),
        value.approval.reservation_current_exchange.as_ref(),
    )?;
    authority_request(
        value.approval.approval_request_json.as_deref(),
        value.approval.approval_request.as_ref(),
        value.approval.approval_exchange.as_ref(),
    )?;
    authority_request(
        value.approval.final_request_json.as_deref(),
        value.approval.final_request.as_ref(),
        value.approval.final_exchange.as_ref(),
    )?;
    crate::independent_approve_state_wire_authority::exact(value)?;
    crate::independent_approve_state_wire_central::exact(value)
}

fn current(
    request: Option<&AuthorityRequestV1>,
    exchange: Option<&crowsi_credential_authority_contracts::SignedAuthorityExchangeV1>,
) -> Result<(), AgentError> {
    let Some(request) = request else {
        return Ok(());
    };
    crate::current_request_validation::exact(request, exchange.map(|item| &item.request))
}

fn authority_request(
    wire: Option<&str>,
    request: Option<&AuthorityRequestV1>,
    exchange: Option<&crowsi_credential_authority_contracts::SignedAuthorityExchangeV1>,
) -> Result<(), AgentError> {
    let Some(wire) = wire else {
        return Ok(());
    };
    let decoded = decode_authority_request_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    (request == Some(&decoded) && exchange.is_none_or(|item| item.request == decoded))
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}
