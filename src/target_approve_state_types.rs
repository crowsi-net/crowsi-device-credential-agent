use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, ManagementProjectionV2, ManagementRequestV2,
    SignedAuthorityExchangeV1, SignedTargetDeviceProofV2,
};
use crowsi_windows_operation_contracts::{
    OperationAuthorizeOnceRequestV2, OperationOnlyRequest, OperationOnlyResponse,
};
use ihat_identity_assertion_contracts::AuthorityRequestV1;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum TargetApprovePhaseV1 {
    FinishPrepared,
    FinishInvoking,
    FinishUnknown,
    CurrentRequestPrepared,
    CurrentPrepared,
    CurrentInvoking,
    CurrentUnknown,
    CurrentObservePrepared,
    CurrentObserveInvoking,
    CurrentObserveUnknown,
    PaPrepared,
    PaInvoking,
    PaUnknown,
    CustodyPrepared,
    CustodyInvoking,
    CustodyUnknown,
    CentralPrepared,
    CentralInvoking,
    Unknown,
    Complete,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TargetApproveRecordV1 {
    pub operation_id: String,
    pub browser_request: ManagementRequestV2,
    pub browser_request_digest_sha256: String,
    pub phase: TargetApprovePhaseV1,
    pub finish_request: AuthorityRequestV1,
    pub finish_exchange: Option<SignedAuthorityExchangeV1>,
    pub current_request: Option<AuthorityRequestV1>,
    pub current_exchange: Option<SignedAuthorityExchangeV1>,
    pub current_observed_at_epoch_s: Option<u64>,
    pub pa_request_json: Option<String>,
    pub pa_request: Option<OperationAuthorizeOnceRequestV2>,
    pub pa_response_json: Option<String>,
    pub pa_response: Option<OperationOnlyRequest>,
    pub custody_response_json: Option<String>,
    pub custody_response: Option<OperationOnlyResponse>,
    pub target_proof: Option<SignedTargetDeviceProofV2>,
    pub central_envelope_json: Option<String>,
    pub central_envelope: Option<EndpointManagementEnvelopeV2>,
    pub response_json: Option<String>,
    pub response: Option<ManagementProjectionV2>,
    pub expires_at_epoch_s: u64,
    pub updated_at_epoch_s: u64,
}

pub(super) struct TargetApproveResume {
    pub selected_identity: SignedAuthorityExchangeV1,
    pub selected_begin: SignedAuthorityExchangeV1,
    pub lookup: crate::actor_options_state_types::ActorPreparedLookupV1,
    pub actor_projection: ManagementProjectionV2,
    pub approval: Box<TargetApproveRecordV1>,
}
