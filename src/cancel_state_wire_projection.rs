use crowsi_credential_authority_contracts::{
    ManagementCommandV2, ManagementOperationState, ManagementProjectionBodyV2,
};

use crate::{AgentError, cancel_state_types::CancelRecordV1};

pub(super) fn exact(value: &CancelRecordV1) -> Result<(), AgentError> {
    let Some(body) = value.cancelled_projection_body.as_ref() else {
        return Ok(());
    };
    let ManagementProjectionBodyV2::Operation { operation } = body else {
        return Err(AgentError::AuthorityRollback);
    };
    let ManagementCommandV2::Cancel {
        operation_id,
        expected_state_revision,
    } = &value.browser_request.command
    else {
        return Err(AgentError::AuthorityRollback);
    };
    let revision = expected_state_revision
        .checked_add(1)
        .ok_or(AgentError::AuthorityRollback)?;
    let exact = operation.operation_id == *operation_id
        && operation.state == ManagementOperationState::Cancelled
        && operation.state_revision == revision;
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}
