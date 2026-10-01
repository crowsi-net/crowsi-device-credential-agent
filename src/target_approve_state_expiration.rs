use ihat_identity_assertion_contracts::AuthorityEvidence;

use crate::{AgentError, target_approve_state_types::TargetApproveResume};

pub(super) fn expiration(value: &TargetApproveResume) -> Result<u64, AgentError> {
    let mut expires = crate::target_approve_state::selected_expiration(value)?;
    let record = &value.approval;
    if let Some(finish) = &record.finish_exchange {
        let fresh = crowsi_credential_authority_contracts::fresh_uv_from_finish_exchange(
            finish,
            &record.browser_request.command,
        )
        .map_err(|_| AgentError::AuthorityRollback)?;
        expires = expires
            .min(finish.response.expires_at_epoch_s)
            .min(fresh.expires_at_epoch_s);
    }
    if let Some(request) = &record.current_request {
        for proof in &request.evidence {
            let AuthorityEvidence::Signed(proof) = proof else {
                return Err(AgentError::AuthorityRollback);
            };
            expires = expires.min(proof.expires_at_epoch_s);
        }
    }
    if let Some(current) = &record.current_exchange {
        let identity =
            crowsi_credential_authority_contracts::identity_evidence_from_exchange(current)
                .map_err(|_| AgentError::AuthorityRollback)?;
        expires = expires
            .min(current.response.expires_at_epoch_s)
            .min(identity.assertion.expires_at_epoch_s)
            .min(identity.current_status.expires_at_epoch_s);
    }
    if let Some(request) = &record.pa_request {
        expires = expires.min(request.target_device_proof.expires_at_epoch_s);
    }
    if let Some(response) = &record.pa_response {
        expires = expires.min(response.pa_authorization.expires_at_epoch_s);
    }
    if let Some(proof) = &record.target_proof {
        expires = expires.min(proof.binding.expires_at_epoch_s);
    }
    Ok(expires)
}
