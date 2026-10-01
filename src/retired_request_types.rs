use crowsi_credential_authority_contracts::{
    EndpointRevocationExecutionCancellationCleanupCompleteV1, ManagementProjectionBodyV2,
    ManagementProjectionV2,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RetiredRefreshMaterialV1 {
    ManagementEnvelope(RetiredManagementEnvelopeV1),
    CancelEnvelope(RetiredCancelEnvelopeV1),
    CancelCleanupComplete(RetiredCancelCleanupCompleteV1),
    RevocationFinalize(RetiredRevocationFinalizeV1),
    IndependentRevocationFinalize(RetiredIndependentRevocationFinalizeV1),
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetiredManagementEnvelopeV1 {
    pub route: String,
    pub wire: String,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetiredCancelEnvelopeV1 {
    pub wire: String,
    pub expected_body: ManagementProjectionBodyV2,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetiredCancelCleanupCompleteV1 {
    pub wire: String,
    pub expected_body: ManagementProjectionBodyV2,
    pub cleanup_complete_request_sha256: String,
    pub acknowledge_result_digest_sha256: String,
    pub delivery: EndpointRevocationExecutionCancellationCleanupCompleteV1,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetiredRevocationFinalizeV1 {
    pub wire: String,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetiredIndependentRevocationFinalizeV1 {
    pub wire: String,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetiredRequestReceiptV1 {
    pub browser_request_digest_sha256: String,
    pub operation_id: String,
    pub route: String,
    pub refresh_material: Option<RetiredRefreshMaterialV1>,
    pub response_json: Option<String>,
    pub response: Option<ManagementProjectionV2>,
    pub refresh_until_epoch_s: u64,
    pub retired_at_epoch_s: u64,
    pub retain_until_epoch_s: u64,
}
