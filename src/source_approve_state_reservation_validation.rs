use crowsi_credential_authority_contracts::identity_evidence_from_exchange;

use crate::{
    AgentError, source_approve_state_types::SourceApproveRecordV1,
    source_options_state_types::PreparedSourceOptionsV1,
};

pub(super) fn valid(
    value: &SourceApproveRecordV1,
    source: &PreparedSourceOptionsV1,
) -> Result<(), AgentError> {
    if let Some(request) = value.reservation_current_request.as_ref() {
        crate::current_request_validation::exact(
            request,
            value
                .reservation_current_exchange
                .as_ref()
                .map(|exchange| &exchange.request),
        )?;
    }
    if let Some(exchange) = value.reservation_current_exchange.as_ref() {
        let first = value
            .current_exchange
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?;
        let old =
            identity_evidence_from_exchange(first).map_err(|_| AgentError::AuthorityRollback)?;
        let new =
            identity_evidence_from_exchange(exchange).map_err(|_| AgentError::AuthorityRollback)?;
        let exact = first != exchange
            && first.request != exchange.request
            && old.assertion.device_id == new.assertion.device_id
            && old.assertion.service_id == new.assertion.service_id
            && old.assertion.pairwise_subject == new.assertion.pairwise_subject
            && new.assertion.device_id == source.prepared.source_device_ref;
        if !exact {
            return Err(AgentError::AuthorityRollback);
        }
    }
    observed(value)?;
    value
        .execution_reservation_trust
        .as_ref()
        .is_none_or(|pin| pin.accepted_at_epoch_s <= value.updated_at_epoch_s)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}

fn observed(value: &SourceApproveRecordV1) -> Result<(), AgentError> {
    let Some(at) = value.reservation_current_observed_at_epoch_s else {
        return Ok(());
    };
    let exchange = value
        .reservation_current_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let expires = crate::source_approve_state_finalization::begin_expiration(value)
        .ok_or(AgentError::AuthorityRollback)?;
    (exchange.response.issued_at_epoch_s <= at && at <= value.updated_at_epoch_s && at < expires)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}
