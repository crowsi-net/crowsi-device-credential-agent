use crowsi_credential_authority_contracts::{
    ManagementIntentV2, ManagementLifecycleV2, ManagementSnapshotV2,
};
use ihat_identity_assertion_contracts::IdentityEvidenceMetadata;

use crate::AgentError;

pub(super) fn validate(
    snapshot: &ManagementSnapshotV2,
    revision: u64,
    intent: &ManagementIntentV2,
    identity: &IdentityEvidenceMetadata,
) -> Result<(), AgentError> {
    if expected_revision(intent) != revision || !source_is_current(snapshot, identity) {
        return Err(AgentError::AuthorityRollback);
    }
    match intent {
        ManagementIntentV2::DeviceTransfer {
            service_id,
            target_device_ref,
            credential_refs,
            ..
        } => transfer(
            snapshot,
            service_id,
            target_device_ref,
            credential_refs,
            identity,
        ),
        ManagementIntentV2::DeviceRevocation {
            target_device_ref,
            expected_device_revocation_epoch,
            ..
        } => device(
            snapshot,
            target_device_ref,
            *expected_device_revocation_epoch,
        ),
        ManagementIntentV2::SessionRevocation {
            target_session_ref,
            expected_session_revocation_epoch,
            ..
        } => session(
            snapshot,
            target_session_ref,
            *expected_session_revocation_epoch,
        )
        .map(|_| ()),
    }
}

fn source_is_current(snapshot: &ManagementSnapshotV2, value: &IdentityEvidenceMetadata) -> bool {
    let assertion = &value.assertion;
    let device = snapshot
        .devices
        .iter()
        .find(|item| item.device_ref == assertion.device_id);
    let session = snapshot
        .sessions
        .iter()
        .find(|item| item.session_ref == assertion.session_ref);
    matches!(device, Some(item) if item.status == ManagementLifecycleV2::Active
        && item.device_revocation_epoch == assertion.revocation_epochs.device
        && item.posture_revision == assertion.device_posture.revision)
        && matches!(session, Some(item) if item.status == ManagementLifecycleV2::Active
            && item.device_ref == assertion.device_id
            && item.session_revocation_epoch == assertion.revocation_epochs.session)
}

fn transfer(
    snapshot: &ManagementSnapshotV2,
    service: &str,
    target: &str,
    credentials: &[String],
    identity: &IdentityEvidenceMetadata,
) -> Result<(), AgentError> {
    if credentials.len() != 1
        || target == identity.assertion.device_id
        || !snapshot
            .devices
            .iter()
            .any(|item| item.device_ref == target && item.status == ManagementLifecycleV2::Active)
        || credentials.iter().any(|reference| {
            !snapshot.credentials.iter().any(|item| {
                item.credential_ref == *reference
                    && item.provider == service
                    && item.status == ManagementLifecycleV2::Active
                    && item
                        .assigned_device_refs
                        .contains(&identity.assertion.device_id)
                    && item.scopes.len() == 1
            })
        })
    {
        Err(AgentError::RequestInvalid)
    } else {
        Ok(())
    }
}

fn device(snapshot: &ManagementSnapshotV2, target: &str, epoch: u64) -> Result<(), AgentError> {
    snapshot
        .devices
        .iter()
        .any(|item| {
            item.device_ref == target
                && item.status == ManagementLifecycleV2::Active
                && item.device_revocation_epoch == epoch
        })
        .then_some(())
        .ok_or(AgentError::RequestInvalid)
}

pub(super) fn session<'a>(
    snapshot: &'a ManagementSnapshotV2,
    target: &str,
    epoch: u64,
) -> Result<&'a crowsi_credential_authority_contracts::ManagementSessionV2, AgentError> {
    snapshot
        .sessions
        .iter()
        .find(|item| {
            item.session_ref == target
                && item.status == ManagementLifecycleV2::Active
                && item.session_revocation_epoch == epoch
        })
        .ok_or(AgentError::RequestInvalid)
}

fn expected_revision(value: &ManagementIntentV2) -> u64 {
    match value {
        ManagementIntentV2::DeviceTransfer {
            expected_snapshot_revision,
            ..
        }
        | ManagementIntentV2::DeviceRevocation {
            expected_snapshot_revision,
            ..
        }
        | ManagementIntentV2::SessionRevocation {
            expected_snapshot_revision,
            ..
        } => *expected_snapshot_revision,
    }
}
