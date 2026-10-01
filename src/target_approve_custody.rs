use crowsi_windows_operation_contracts::{
    CustodyClient, HelperIdentity, OperationOnlyResponse, decode_operation_request,
};
use std::time::Duration;

use crate::{
    AgentError, config::AgentConfigDocument, target_approve_state_types::TargetApproveResume,
};

pub(super) fn sign(
    config: &AgentConfigDocument,
    value: &TargetApproveResume,
) -> Result<(Vec<u8>, OperationOnlyResponse), AgentError> {
    let wire = value
        .approval
        .pa_response_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?;
    let request =
        decode_operation_request(wire.as_bytes()).map_err(|_| AgentError::AuthorityRollback)?;
    if value.approval.pa_response.as_ref() != Some(&request) {
        return Err(AgentError::AuthorityRollback);
    }
    let key = crate::target_approve_key::device_key(config, value)?;
    let helper = HelperIdentity::new(
        key.custody_executable.clone(),
        key.custody_executable_sha256.clone(),
    )
    .map_err(|_| AgentError::AuthorityUnavailable)?;
    let client = CustodyClient::new(
        helper,
        Duration::from_millis(config.pa_authorization_route.timeout_ms),
    )
    .map_err(|_| AgentError::ConfigInvalid)?;
    let response = client
        .execute_operation(&request)
        .map_err(|_| AgentError::AuthorityUnavailable)?;
    let response_wire = serde_json::to_vec(&response).map_err(|_| AgentError::ResponseInvalid)?;
    if response_wire.len() > crate::source_options_state::MAXIMUM_PHASE_WIRE_BYTES {
        return Err(AgentError::ResponseInvalid);
    }
    Ok((response_wire, response))
}
