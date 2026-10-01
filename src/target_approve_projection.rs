use crowsi_credential_authority_contracts::{
    ActorRequirementV2, ManagementOperationState, ManagementProjectionBodyV2,
    ManagementProjectionV2, ManagementReasonCode, RequiredActorRole,
};

use crate::{AgentError, target_approve_state_types::TargetApproveResume};

pub(crate) fn exact(
    value: &TargetApproveResume,
    projection: &ManagementProjectionV2,
) -> Result<(), AgentError> {
    let ManagementProjectionBodyV2::Operation { operation: prior } = &value.actor_projection.body
    else {
        return Err(AgentError::AuthorityRollback);
    };
    if prior.state != ManagementOperationState::AwaitingTargetUv {
        return Err(AgentError::AuthorityRollback);
    }
    let mut expected = prior.clone();
    expected.state_revision = expected
        .state_revision
        .checked_add(1)
        .ok_or(AgentError::AuthorityRollback)?;
    expected.state = ManagementOperationState::Unknown;
    expected.reason = Some(ManagementReasonCode::ProviderOutcomeUnknown);
    expected.webauthn_options = None;
    expected.reconcile_digest = Some(reconcile(value)?);
    expected.actor = ActorRequirementV2 {
        role: RequiredActorRole::ReconcileOnly,
        required_actor_device_ref: None,
        required_approval_authority_ref: None,
        excluded_actor_device_refs: Vec::new(),
    };
    let snapshot = value
        .actor_projection
        .snapshot_revision
        .checked_add(1)
        .ok_or(AgentError::AuthorityRollback)?;
    let exact = projection.snapshot_revision >= snapshot
        && matches!(&projection.body, ManagementProjectionBodyV2::Operation { operation }
            if operation == &expected);
    exact.then_some(()).ok_or(AgentError::ResponseInvalid)
}

fn reconcile(value: &TargetApproveResume) -> Result<String, AgentError> {
    let prepared = &value.lookup.response.prepared;
    let wire = serde_json::to_vec(&(
        "CROWSI-MANAGEMENT-RECONCILE-V2",
        &prepared.operation_id,
        prepared,
    ))
    .map_err(|_| AgentError::ResponseInvalid)?;
    Ok(crate::crypto::digest(&wire)
        .trim_start_matches("sha256:")
        .to_owned())
}
