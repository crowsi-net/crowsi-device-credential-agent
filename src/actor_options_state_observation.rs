use crate::actor_options_state_types::ActorOptionsRecordV1;

pub(super) fn valid(value: &ActorOptionsRecordV1) -> bool {
    value.current_observed_at_epoch_s.is_none_or(|observed| {
        value.current_exchange.as_ref().is_some_and(|current| {
            current.response.issued_at_epoch_s <= observed
                && observed <= value.updated_at_epoch_s
                && observed < value.expires_at_epoch_s
        })
    })
}
