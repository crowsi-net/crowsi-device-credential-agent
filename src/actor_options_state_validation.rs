use crowsi_credential_authority_contracts::{ManagementCommandV2, management_command_digest};

use crate::{
    AgentError,
    actor_options_state_types::{ActorOptionsPhaseV1, ActorOptionsRecordV1},
    source_options_state_types::{FreshUvAttemptsV1, OperationJournalV1, PreparedOperationsV1},
};

pub(super) fn all(
    prepared: &PreparedOperationsV1,
    fresh: &FreshUvAttemptsV1,
    journal: &OperationJournalV1,
) -> Result<(), AgentError> {
    let indexes = journal
        .actor_options_index
        .iter()
        .all(|(request, operation)| {
            journal
                .actor_options
                .get(operation)
                .is_some_and(|value| value.browser_request.request_id == *request)
        });
    let records = journal.actor_options.iter().all(|(operation, value)| {
        record(
            operation,
            value,
            prepared.actor_records.get(operation),
            fresh.actor_records.get(operation),
        )
        .is_ok()
    });
    let no_orphans = prepared
        .actor_records
        .keys()
        .all(|key| journal.actor_options.contains_key(key))
        && fresh
            .actor_records
            .keys()
            .all(|key| journal.actor_options.contains_key(key));
    (indexes && records && no_orphans)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}

fn record(
    operation: &str,
    value: &ActorOptionsRecordV1,
    prepared: Option<&crate::actor_options_state_types::ActorPreparedLookupV1>,
    fresh: Option<&crate::source_options_state_types::FreshUvAttemptV1>,
) -> Result<(), AgentError> {
    let digest = management_command_digest(&value.browser_request)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let (id, revision) = match &value.browser_request.command {
        ManagementCommandV2::TargetOptions {
            operation_id,
            expected_state_revision,
        }
        | ManagementCommandV2::ApprovalOptions {
            operation_id,
            expected_state_revision,
        } => (operation_id, expected_state_revision),
        _ => return Err(AgentError::AuthorityRollback),
    };
    let historic =
        crate::fresh_uv_options::actor_historic(value.phase, fresh, value.updated_at_epoch_s)?;
    let base = operation == value.operation_id
        && id == operation
        && *revision > 0
        && value.browser_request_digest_sha256 == digest
        && value.expires_at_epoch_s
            == crate::actor_options_state::expiration(value, prepared, fresh)?
        && (value.updated_at_epoch_s <= value.expires_at_epoch_s || historic);
    if !base
        || !crate::actor_options_state_observation::valid(value)
        || !phase(value, prepared, fresh)
    {
        return Err(AgentError::AuthorityRollback);
    }
    crate::actor_options_state_wire::exact(value, prepared, fresh)
}

fn phase(
    value: &ActorOptionsRecordV1,
    prepared: Option<&crate::actor_options_state_types::ActorPreparedLookupV1>,
    fresh: Option<&crate::source_options_state_types::FreshUvAttemptV1>,
) -> bool {
    let current = value.current_exchange.is_some();
    let observed = value.current_observed_at_epoch_s.is_some();
    let lookup = value.lookup_request.is_some();
    let prepared = prepared.is_some();
    let fresh_request = fresh.is_some();
    let fresh_exchange = fresh.and_then(|item| item.exchange.as_ref()).is_some();
    let envelope = value.central_envelope.is_some() && value.central_envelope_json.is_some();
    let response = value.response.is_some() && value.response_json.is_some();
    match value.phase {
        ActorOptionsPhaseV1::CurrentPrepared
        | ActorOptionsPhaseV1::CurrentInvoking
        | ActorOptionsPhaseV1::CurrentUnknown => {
            !current
                && !observed
                && !lookup
                && !prepared
                && !fresh_request
                && !envelope
                && !response
        }
        ActorOptionsPhaseV1::CurrentObservePrepared
        | ActorOptionsPhaseV1::CurrentObserveInvoking
        | ActorOptionsPhaseV1::CurrentObserveUnknown => {
            current && !observed && !lookup && !prepared && !fresh_request && !envelope && !response
        }
        ActorOptionsPhaseV1::LookupPrepared => {
            current && observed && lookup && !prepared && !fresh_request && !envelope && !response
        }
        ActorOptionsPhaseV1::BeginPrepared => {
            current
                && observed
                && lookup
                && prepared
                && fresh_request
                && !fresh_exchange
                && !envelope
                && !response
        }
        ActorOptionsPhaseV1::CentralPrepared
        | ActorOptionsPhaseV1::CentralInvoking
        | ActorOptionsPhaseV1::Unknown => {
            current
                && observed
                && lookup
                && prepared
                && fresh_request
                && fresh_exchange
                && envelope
                && !response
        }
        ActorOptionsPhaseV1::Complete => {
            current
                && observed
                && lookup
                && prepared
                && fresh_request
                && fresh_exchange
                && envelope
                && response
        }
    }
}
