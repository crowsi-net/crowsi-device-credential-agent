use crowsi_credential_authority_contracts::{
    ActorRequirementV2, ManagementIntentV2, ManagementOperationState, ManagementProjectionBodyV2,
    ManagementProjectionV2, RequiredActorRole,
};

use crate::{AgentError, source_approve_state_types::SourceApproveResume};

pub(crate) fn exact(
    value: &SourceApproveResume,
    projection: &ManagementProjectionV2,
) -> Result<(), AgentError> {
    let ManagementProjectionBodyV2::Operation { operation: prior } = &value.source_projection.body
    else {
        return Err(AgentError::AuthorityRollback);
    };
    let mut expected = prior.clone();
    let ManagementProjectionBodyV2::Operation { operation: actual } = &projection.body else {
        return Err(AgentError::ResponseInvalid);
    };
    if expected.state != ManagementOperationState::AwaitingSourceUv || expected.state_revision != 1
    {
        return Err(AgentError::AuthorityRollback);
    }
    expected.state_revision = 2;
    expected.webauthn_options = None;
    transition(value, &mut expected, actual)?;
    let expected_revision = value
        .source_projection
        .snapshot_revision
        .checked_add(1)
        .ok_or(AgentError::AuthorityRollback)?;
    let exact = projection.snapshot_revision >= expected_revision && actual == &expected;
    exact.then_some(()).ok_or(AgentError::ResponseInvalid)
}

fn transition(
    value: &SourceApproveResume,
    operation: &mut crowsi_credential_authority_contracts::ManagementOperationV2,
    actual: &crowsi_credential_authority_contracts::ManagementOperationV2,
) -> Result<(), AgentError> {
    let prepared = &value.source.prepared;
    match &prepared.intent {
        ManagementIntentV2::DeviceTransfer {
            target_device_ref, ..
        } => {
            operation.state = ManagementOperationState::AwaitingTarget;
            operation.reason = None;
            operation.reconcile_digest = None;
            operation.actor = actor(
                RequiredActorRole::TargetDevice,
                Some(target_device_ref.clone()),
                None,
                vec![prepared.source_device_ref.clone()],
            );
        }
        ManagementIntentV2::DeviceRevocation { .. }
        | ManagementIntentV2::SessionRevocation { .. } => revocation(value, operation, actual)?,
    }
    Ok(())
}

fn revocation(
    value: &SourceApproveResume,
    operation: &mut crowsi_credential_authority_contracts::ManagementOperationV2,
    actual: &crowsi_credential_authority_contracts::ManagementOperationV2,
) -> Result<(), AgentError> {
    let prepared = &value.source.prepared;
    let requirements = prepared
        .revocation
        .as_ref()
        .ok_or(AgentError::ResponseInvalid)?;
    if requirements.target_device_ref == prepared.source_device_ref {
        operation.state = ManagementOperationState::AwaitingRevocationFinal;
        operation.reason = None;
        operation.reconcile_digest = actual.reconcile_digest.clone();
        operation.actor = actor(RequiredActorRole::ReconcileOnly, None, None, Vec::new());
    } else {
        operation.state = ManagementOperationState::AwaitingIndependentApproval;
        operation.reason = None;
        operation.reconcile_digest = None;
        operation.actor = actor(
            RequiredActorRole::IndependentApproval,
            None,
            requirements.required_approval_authority_ref.clone(),
            vec![
                prepared.source_device_ref.clone(),
                requirements.target_device_ref.clone(),
            ],
        );
    }
    Ok(())
}

fn actor(
    role: RequiredActorRole,
    device: Option<String>,
    authority: Option<String>,
    excluded: Vec<String>,
) -> ActorRequirementV2 {
    ActorRequirementV2 {
        role,
        required_actor_device_ref: device,
        required_approval_authority_ref: authority,
        excluded_actor_device_refs: excluded,
    }
}
