use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementOperationKind, ManagementOperationScopeV2,
    ManagementProjectionV2, ManagementRequestV2, SignedAuthorityExchangeV1,
};
use ihat_identity_assertion_contracts::AuthorityRequestV1;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreparedSourceOptionsV1 {
    pub browser_request: ManagementRequestV2,
    pub browser_request_digest_sha256: String,
    pub prepared: EndpointPreparedOperationV2,
    pub expected_operation_kind: ManagementOperationKind,
    pub expected_operation_scope: ManagementOperationScopeV2,
    pub selected_identity_exchange: SignedAuthorityExchangeV1,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FreshUvAttemptV1 {
    pub operation_id: String,
    pub request: AuthorityRequestV1,
    pub exchange: Option<SignedAuthorityExchangeV1>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SourceOptionsPhaseV1 {
    BeginPrepared,
    CentralPrepared,
    CentralInvoking,
    Unknown,
    Complete,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceOptionsJournalRecordV1 {
    pub operation_id: String,
    pub browser_request_id: String,
    pub browser_request_digest_sha256: String,
    pub phase: SourceOptionsPhaseV1,
    pub central_envelope_json: Option<String>,
    pub central_envelope_digest_sha256: Option<String>,
    pub response_json: Option<String>,
    pub response: Option<ManagementProjectionV2>,
    pub expires_at_epoch_s: u64,
    pub updated_at_epoch_s: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreparedOperationsV1 {
    pub schema: String,
    pub records: BTreeMap<String, PreparedSourceOptionsV1>,
    pub actor_records: BTreeMap<String, crate::actor_options_state_types::ActorPreparedLookupV1>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FreshUvAttemptsV1 {
    pub schema: String,
    pub records: BTreeMap<String, FreshUvAttemptV1>,
    pub actor_records: BTreeMap<String, FreshUvAttemptV1>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperationJournalV1 {
    pub schema: String,
    pub request_index: BTreeMap<String, String>,
    pub records: BTreeMap<String, SourceOptionsJournalRecordV1>,
    pub source_approval_index: BTreeMap<String, String>,
    pub source_approvals:
        BTreeMap<String, Box<crate::source_approve_state_types::SourceApproveRecordV1>>,
    pub actor_options_index: BTreeMap<String, String>,
    pub actor_options:
        BTreeMap<String, Box<crate::actor_options_state_types::ActorOptionsRecordV1>>,
    pub cancellation_index: BTreeMap<String, String>,
    pub cancellations: BTreeMap<String, Box<crate::cancel_state_types::CancelRecordV1>>,
    pub cancel_request_tombstones:
        BTreeMap<String, crate::cancel_state_types::CancelRequestTombstoneV1>,
    pub target_approval_index: BTreeMap<String, String>,
    pub target_approvals:
        BTreeMap<String, Box<crate::target_approve_state_types::TargetApproveRecordV1>>,
    pub independent_approval_index: BTreeMap<String, String>,
    pub independent_approvals:
        BTreeMap<String, Box<crate::independent_approve_state_types::IndependentApproveRecordV1>>,
    pub reconciliation_index: BTreeMap<String, String>,
    pub reconciliations: BTreeMap<String, Box<crate::reconcile_state_types::ReconcileRecordV1>>,
    pub reconcile_request_tombstones:
        BTreeMap<String, crate::reconcile_state_types::ReconcileRequestTombstoneV1>,
    pub retired_request_receipts:
        BTreeMap<String, crate::retired_request_types::RetiredRequestReceiptV1>,
}

pub(super) struct SourceOptionsResume {
    pub prepared: Box<PreparedSourceOptionsV1>,
    pub fresh_uv: Box<FreshUvAttemptV1>,
    pub journal: Box<SourceOptionsJournalRecordV1>,
}

impl PreparedOperationsV1 {
    pub fn empty() -> Self {
        Self {
            schema: "crowsi://device-agent/prepared-operations/v3".into(),
            records: BTreeMap::new(),
            actor_records: BTreeMap::new(),
        }
    }
}

impl FreshUvAttemptsV1 {
    pub fn empty() -> Self {
        Self {
            schema: "crowsi://device-agent/fresh-uv-attempts/v2".into(),
            records: BTreeMap::new(),
            actor_records: BTreeMap::new(),
        }
    }
}

impl OperationJournalV1 {
    pub fn empty() -> Self {
        Self {
            schema: "crowsi://device-agent/operation-journal/v5".into(),
            request_index: BTreeMap::new(),
            records: BTreeMap::new(),
            source_approval_index: BTreeMap::new(),
            source_approvals: BTreeMap::new(),
            actor_options_index: BTreeMap::new(),
            actor_options: BTreeMap::new(),
            cancellation_index: BTreeMap::new(),
            cancellations: BTreeMap::new(),
            cancel_request_tombstones: BTreeMap::new(),
            target_approval_index: BTreeMap::new(),
            target_approvals: BTreeMap::new(),
            independent_approval_index: BTreeMap::new(),
            independent_approvals: BTreeMap::new(),
            reconciliation_index: BTreeMap::new(),
            reconciliations: BTreeMap::new(),
            reconcile_request_tombstones: BTreeMap::new(),
            retired_request_receipts: BTreeMap::new(),
        }
    }
}
