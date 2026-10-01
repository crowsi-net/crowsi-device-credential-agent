use crate::{AgentError, identity_locator::IdentitySessionLocatorV1, replay::DurableLedger};

pub(crate) struct IdentityLocatorStore<'a> {
    ledger: &'a DurableLedger,
}

impl<'a> IdentityLocatorStore<'a> {
    pub(super) fn new(ledger: &'a DurableLedger) -> Self {
        Self { ledger }
    }

    pub(super) fn load_value(&self) -> Result<Option<IdentitySessionLocatorV1>, AgentError> {
        self.ledger.load_namespace("identity-session-locator")
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn create_value(&self, next: &IdentitySessionLocatorV1) -> Result<(), AgentError> {
        self.ledger.transaction_namespaces(|values| {
            create_in(values, next)?;
            Ok(((), true))
        })
    }

    #[cfg(test)]
    pub(super) fn compare_and_swap_test(
        &self,
        expected: &IdentitySessionLocatorV1,
        next: &IdentitySessionLocatorV1,
    ) -> Result<(), AgentError> {
        self.compare_and_swap_value(expected, next)
    }

    pub(super) fn observe_current_value(
        &self,
        expected: &IdentitySessionLocatorV1,
        next: &IdentitySessionLocatorV1,
    ) -> Result<(), AgentError> {
        crate::identity_locator_validation::current(expected, next)?;
        self.compare_and_swap_value(expected, next)
    }

    fn compare_and_swap_value(
        &self,
        expected: &IdentitySessionLocatorV1,
        next: &IdentitySessionLocatorV1,
    ) -> Result<(), AgentError> {
        self.ledger.transaction_namespaces(|values| {
            compare_and_swap_in(values, expected, next)?;
            Ok(((), true))
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
fn create_in(
    values: &mut crate::replay_namespace::SecurityNamespaces,
    next: &IdentitySessionLocatorV1,
) -> Result<(), AgentError> {
    if values
        .get::<IdentitySessionLocatorV1>("identity-session-locator")?
        .is_some()
    {
        return Err(AgentError::AuthorityRollback);
    }
    values.put("identity-session-locator", next)
}

fn compare_and_swap_in(
    values: &mut crate::replay_namespace::SecurityNamespaces,
    expected: &IdentitySessionLocatorV1,
    next: &IdentitySessionLocatorV1,
) -> Result<(), AgentError> {
    if values
        .get::<IdentitySessionLocatorV1>("identity-session-locator")?
        .as_ref()
        != Some(expected)
    {
        return Err(AgentError::AuthorityRollback);
    }
    values.put("identity-session-locator", next)
}

pub(crate) fn observe_projection_in(
    values: &mut crate::replay_namespace::SecurityNamespaces,
    config: &crate::config::AgentConfigDocument,
    projection: &crowsi_credential_authority_contracts::ManagementProjectionV2,
    now: u64,
) -> Result<(), AgentError> {
    let current: IdentitySessionLocatorV1 = values
        .get("identity-session-locator")?
        .ok_or(AgentError::IdentityUnavailable)?;
    crate::identity_locator_validation::historic(config, &current)?;
    let exact = projection.current_device_ref == current.device_id
        && projection.current_session_ref == current.session_ref
        && projection.subject_revocation_epoch == current.subject_revocation_epoch
        && projection.service_revocation_epoch == current.service_revocation_epoch
        && projection.device_revocation_epoch == current.device_revocation_epoch
        && projection.session_revocation_epoch == current.session_revocation_epoch
        && projection.device_posture_state == current.device_posture_state
        && projection.device_posture_revision == current.device_posture_revision
        && projection.device_proof_key_ref == current.device_proof_key_ref;
    if !exact || now < current.updated_at_epoch_s {
        return Err(AgentError::AuthorityRollback);
    }
    if current.response_config_generation < config.minimum_identity_config_generation {
        return Ok(());
    }
    let mut next = current.clone();
    next.updated_at_epoch_s = now;
    crate::identity_locator_validation::current(&current, &next)?;
    values.put("identity-session-locator", &next)
}
