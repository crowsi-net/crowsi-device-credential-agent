use crowsi_credential_authority_contracts::{
    ManagementProjectionBodyV2, ManagementProjectionV2, ManagementSnapshotV2,
};
use serde::{Deserialize, Serialize};

use crate::{AgentError, crypto, replay::DurableLedger, replay_namespace::SecurityNamespaces};

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionRecord {
    subject_revocation_epoch: u64,
    service_revocation_epoch: u64,
    device_revocation_epoch: u64,
    session_revocation_epoch: u64,
    device_posture_revision: u64,
    snapshot_revision: u64,
    issued_at_epoch_s: u64,
    snapshot_digest: Option<String>,
    snapshot: Option<ManagementProjectionV2>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CachedManagementSnapshot {
    pub revision: u64,
    pub snapshot: ManagementSnapshotV2,
}

pub(crate) fn observe_in_transaction(
    values: &mut SecurityNamespaces,
    value: &ManagementProjectionV2,
) -> Result<(), AgentError> {
    let current: Option<ProjectionRecord> = values.get("management-projection")?;
    let mut next = record(value)?;
    if current.as_ref().is_some_and(|value| rollback(value, &next)) {
        return Err(AgentError::AuthorityRollback);
    }
    if next.snapshot.is_none() {
        next.snapshot = current.as_ref().and_then(|value| value.snapshot.clone());
        next.snapshot_digest = current.and_then(|value| value.snapshot_digest);
    }
    values.put("management-projection", &next)
}

#[cfg(test)]
pub(crate) fn observe(
    ledger: &DurableLedger,
    value: &ManagementProjectionV2,
) -> Result<(), AgentError> {
    ledger.transaction_namespaces(|values| {
        observe_in_transaction(values, value)?;
        Ok(((), true))
    })
}

pub(crate) fn snapshot(
    ledger: &DurableLedger,
    now: u64,
) -> Result<CachedManagementSnapshot, AgentError> {
    let record: ProjectionRecord = ledger
        .load_namespace("management-projection")?
        .ok_or(AgentError::AuthorityUnavailable)?;
    let projection = record.snapshot.ok_or(AgentError::AuthorityUnavailable)?;
    if projection.issued_at_epoch_s > now || now >= projection.expires_at_epoch_s {
        return Err(AgentError::AuthorityUnavailable);
    }
    match projection.body {
        ManagementProjectionBodyV2::Snapshot { snapshot } => Ok(CachedManagementSnapshot {
            revision: projection.snapshot_revision,
            snapshot,
        }),
        _ => Err(AgentError::AuthorityRollback),
    }
}

fn record(value: &ManagementProjectionV2) -> Result<ProjectionRecord, AgentError> {
    let snapshot =
        matches!(&value.body, ManagementProjectionBodyV2::Snapshot { .. }).then(|| value.clone());
    Ok(ProjectionRecord {
        subject_revocation_epoch: value.subject_revocation_epoch,
        service_revocation_epoch: value.service_revocation_epoch,
        device_revocation_epoch: value.device_revocation_epoch,
        session_revocation_epoch: value.session_revocation_epoch,
        device_posture_revision: value.device_posture_revision,
        snapshot_revision: value.snapshot_revision,
        issued_at_epoch_s: value.issued_at_epoch_s,
        snapshot_digest: snapshot.as_ref().map(snapshot_digest).transpose()?,
        snapshot,
    })
}

fn rollback(current: &ProjectionRecord, next: &ProjectionRecord) -> bool {
    next.subject_revocation_epoch < current.subject_revocation_epoch
        || next.service_revocation_epoch < current.service_revocation_epoch
        || next.device_revocation_epoch < current.device_revocation_epoch
        || next.session_revocation_epoch < current.session_revocation_epoch
        || next.device_posture_revision < current.device_posture_revision
        || next.snapshot_revision < current.snapshot_revision
        || next.issued_at_epoch_s < current.issued_at_epoch_s
        || snapshots_conflict(current, next)
}

fn snapshots_conflict(current: &ProjectionRecord, next: &ProjectionRecord) -> bool {
    matches!(
        (&current.snapshot, &next.snapshot),
        (Some(old), Some(new))
            if old.snapshot_revision == new.snapshot_revision
                && current.snapshot_digest != next.snapshot_digest
    )
}

fn snapshot_digest(value: &ManagementProjectionV2) -> Result<String, AgentError> {
    let ManagementProjectionBodyV2::Snapshot { snapshot } = &value.body else {
        return Err(AgentError::AuthorityResponseInvalid);
    };
    let value = serde_json::to_value(snapshot).map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let wire = crypto::canonical_signed_document("CROWSI-MANAGEMENT-SNAPSHOT-V2", &value)?;
    Ok(crypto::digest(&wire))
}
