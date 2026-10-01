use crowsi_credential_authority_contracts::SignedAuthorityExchangeV1;
use crowsi_credential_authority_contracts::identity_evidence_from_exchange;

use crate::{
    AgentError,
    independent_approve_state_types::{IndependentApproveRecordV1, IndependentApproveResume},
};

pub(super) fn resume(
    actor: &crate::actor_options_state_types::ActorOptionsRecordV1,
    lookup: &crate::actor_options_state_types::ActorPreparedLookupV1,
    begin: &SignedAuthorityExchangeV1,
    value: &IndependentApproveRecordV1,
) -> Result<IndependentApproveResume, AgentError> {
    Ok(IndependentApproveResume {
        selected_identity: actor
            .current_exchange
            .clone()
            .ok_or(AgentError::AuthorityRollback)?,
        selected_begin: begin.clone(),
        lookup: lookup.clone(),
        actor_projection: actor
            .response
            .clone()
            .ok_or(AgentError::AuthorityRollback)?,
        approval: Box::new(value.clone()),
    })
}

pub(super) fn valid(value: &IndependentApproveRecordV1) -> bool {
    value
        .pre_final_trust
        .as_ref()
        .is_none_or(|pin| pin.accepted_at_epoch_s <= value.updated_at_epoch_s)
        && value
            .execution_reservation_trust
            .as_ref()
            .is_none_or(|pin| pin.accepted_at_epoch_s <= value.updated_at_epoch_s)
        && reservation_actor(value)
}

fn reservation_actor(value: &IndependentApproveRecordV1) -> bool {
    let Some(reservation) = value.reservation_current_exchange.as_ref() else {
        return true;
    };
    let Some(approval) = value.current_exchange.as_ref() else {
        return false;
    };
    let (Ok(old), Ok(new)) = (
        identity_evidence_from_exchange(approval),
        identity_evidence_from_exchange(reservation),
    ) else {
        return false;
    };
    approval != reservation
        && approval.request != reservation.request
        && old.assertion.device_id == new.assertion.device_id
        && old.assertion.service_id == new.assertion.service_id
        && old.assertion.pairwise_subject == new.assertion.pairwise_subject
}

pub(super) fn observed(
    at: Option<u64>,
    exchange: Option<&SignedAuthorityExchangeV1>,
    updated: u64,
) -> bool {
    at.is_none_or(|at| {
        exchange.is_some_and(|value| value.response.issued_at_epoch_s <= at && at <= updated)
    })
}
