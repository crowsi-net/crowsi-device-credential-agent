use crowsi_windows_operation_contracts::{
    OperationOnlyRequest, decode_operation_authorize_once_request,
};
use std::time::Duration;

use crate::{
    AgentError, config::AgentConfigDocument, target_approve_state_types::TargetApproveResume,
};

pub(super) fn authorize(
    config: &AgentConfigDocument,
    value: &TargetApproveResume,
    now: u64,
) -> Result<(Vec<u8>, OperationOnlyRequest), AgentError> {
    let stored = value
        .approval
        .pa_request_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?;
    let decoded = decode_operation_authorize_once_request(stored.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    if value.approval.pa_request.as_ref() != Some(&decoded) {
        return Err(AgentError::AuthorityRollback);
    }
    let route = &config.pa_authorization_route;
    let executable = crate::target_approve_process_identity::ProcessIdentity::open(
        &route.executable,
        &route.executable_sha256,
    )?;
    let wire = crate::target_approve_pa_process::invoke(
        &executable,
        &route.config_path,
        &route.config_sha256,
        Duration::from_millis(route.timeout_ms),
        stored.as_bytes(),
    )?;
    let response = crate::target_approve_pa_verify::response(config, value, &wire, now)?;
    Ok((wire, response))
}
