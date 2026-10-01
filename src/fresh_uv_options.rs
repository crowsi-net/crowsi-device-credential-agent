use ihat_identity_assertion_contracts::{AuthorityResult, ResponseOutcome};

use crate::{AgentError, source_options_state_types::FreshUvAttemptV1};

pub(super) fn expires_at(value: &FreshUvAttemptV1) -> Result<Option<u64>, AgentError> {
    let Some(exchange) = &value.exchange else {
        return Ok(None);
    };
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(options),
    } = &exchange.response.outcome
    else {
        return Err(AgentError::AuthorityRollback);
    };
    Ok(Some(options.expires_at_epoch_s))
}

fn permits_historic(
    phase: bool,
    value: Option<&FreshUvAttemptV1>,
    at: u64,
) -> Result<bool, AgentError> {
    Ok(phase
        && value
            .map(expires_at)
            .transpose()?
            .flatten()
            .is_some_and(|expires| at < expires))
}

pub(super) fn actor_historic(
    phase: crate::actor_options_state_types::ActorOptionsPhaseV1,
    value: Option<&FreshUvAttemptV1>,
    at: u64,
) -> Result<bool, AgentError> {
    use crate::actor_options_state_types::ActorOptionsPhaseV1 as P;
    permits_historic(
        matches!(phase, P::CentralInvoking | P::Unknown | P::Complete),
        value,
        at,
    )
}

pub(super) fn source_historic(
    phase: crate::source_options_state::SourceOptionsPhaseV1,
    value: &FreshUvAttemptV1,
    at: u64,
) -> Result<bool, AgentError> {
    use crate::source_options_state::SourceOptionsPhaseV1 as P;
    permits_historic(
        matches!(phase, P::CentralInvoking | P::Unknown | P::Complete),
        Some(value),
        at,
    )
}
