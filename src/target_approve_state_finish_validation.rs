use crowsi_credential_authority_contracts::ManagementCommandV2;
use ihat_identity_assertion_contracts::{AuthorityCommand, decode_authority_request_strict};

use crate::{AgentError, target_approve_state_types::TargetApproveRecordV1};

pub(super) fn valid(value: &TargetApproveRecordV1) -> Result<bool, AgentError> {
    let wire =
        serde_json::to_vec(&value.finish_request).map_err(|_| AgentError::AuthorityRollback)?;
    let request =
        decode_authority_request_strict(&wire).map_err(|_| AgentError::AuthorityRollback)?;
    let AuthorityCommand::FinishFreshUserVerification(command) = &request.command else {
        return Ok(false);
    };
    let ManagementCommandV2::TargetApprove {
        attempt_id,
        assertion,
        ..
    } = &value.browser_request.command
    else {
        return Ok(false);
    };
    let exact = request == value.finish_request
        && request.evidence.is_empty()
        && command.attempt_id == *attempt_id
        && command.credential_id == assertion.credential_id
        && command.client_data_json_base64url == assertion.client_data_json_base64url
        && command.authenticator_data_base64url == assertion.authenticator_data_base64url
        && command.signature_der_base64url == assertion.signature_der_base64url
        && value
            .finish_exchange
            .as_ref()
            .is_none_or(|exchange| exchange.request == request);
    Ok(exact)
}
