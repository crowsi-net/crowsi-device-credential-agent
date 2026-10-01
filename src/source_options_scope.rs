use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementIntentV2, ManagementLifecycleV2,
    ManagementOperationKind, ManagementOperationScopeV2, ManagementProjectionBodyV2,
    ManagementProjectionV2, ManagementSnapshotV2,
};

use crate::AgentError;

pub(crate) fn validate(
    prepared: &EndpointPreparedOperationV2,
    kind: &ManagementOperationKind,
    scope: &ManagementOperationScopeV2,
    projection: &ManagementProjectionV2,
) -> Result<(), AgentError> {
    let ManagementProjectionBodyV2::Operation { operation } = &projection.body else {
        return Err(AgentError::AuthorityResponseInvalid);
    };
    let exact = operation.kind == *kind
        && operation.scope == *scope
        && operation.created_at_epoch_s >= prepared.issued_at_epoch_s
        && operation.created_at_epoch_s == projection.issued_at_epoch_s;
    exact
        .then_some(())
        .ok_or(AgentError::AuthorityResponseInvalid)
}

pub(crate) fn expected(
    prepared: &EndpointPreparedOperationV2,
    snapshot: &ManagementSnapshotV2,
) -> Result<(ManagementOperationKind, ManagementOperationScopeV2), AgentError> {
    match &prepared.intent {
        ManagementIntentV2::DeviceTransfer {
            target_device_ref,
            credential_refs,
            ..
        } => Ok((
            ManagementOperationKind::DeviceTransfer,
            ManagementOperationScopeV2::DeviceTransfer {
                target_device_ref: target_device_ref.clone(),
                credential_refs: credential_refs.clone(),
                expected_source_device_revocation_epoch: device_epoch(
                    snapshot,
                    &prepared.source_device_ref,
                )?,
            },
        )),
        ManagementIntentV2::DeviceRevocation {
            service_id,
            target_device_ref,
            expected_device_revocation_epoch,
            ..
        } => Ok((
            ManagementOperationKind::DeviceRevocation,
            device_revocation(
                snapshot,
                service_id,
                target_device_ref,
                *expected_device_revocation_epoch,
            ),
        )),
        ManagementIntentV2::SessionRevocation {
            target_session_ref,
            expected_session_revocation_epoch,
            ..
        } => {
            let session = snapshot
                .sessions
                .iter()
                .find(|value| value.session_ref == *target_session_ref)
                .ok_or(AgentError::AuthorityResponseInvalid)?;
            Ok((
                ManagementOperationKind::SessionRevocation,
                ManagementOperationScopeV2::SessionRevocation {
                    target_session_ref: target_session_ref.clone(),
                    expected_session_revocation_epoch: *expected_session_revocation_epoch,
                    device_ref: session.device_ref.clone(),
                },
            ))
        }
    }
}

fn device_revocation(
    snapshot: &ManagementSnapshotV2,
    service: &str,
    target: &str,
    epoch: u64,
) -> ManagementOperationScopeV2 {
    let active = |status| status == ManagementLifecycleV2::Active;
    ManagementOperationScopeV2::DeviceRevocation {
        target_device_ref: target.into(),
        expected_device_revocation_epoch: epoch,
        revokes_session_refs: snapshot
            .sessions
            .iter()
            .filter(|value| value.device_ref == target && active(value.status))
            .map(|value| value.session_ref.clone())
            .collect(),
        rotates_credential_refs: snapshot
            .credentials
            .iter()
            .filter(|value| {
                value.provider == service
                    && active(value.status)
                    && value.assigned_device_refs.iter().any(|id| id == target)
            })
            .map(|value| value.credential_ref.clone())
            .collect(),
        preserves_device_refs: snapshot
            .devices
            .iter()
            .filter(|value| value.device_ref != target && active(value.status))
            .map(|value| value.device_ref.clone())
            .collect(),
    }
}

fn device_epoch(snapshot: &ManagementSnapshotV2, device: &str) -> Result<u64, AgentError> {
    snapshot
        .devices
        .iter()
        .find(|value| value.device_ref == device)
        .map(|value| value.device_revocation_epoch)
        .ok_or(AgentError::AuthorityResponseInvalid)
}
