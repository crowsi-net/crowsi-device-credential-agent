use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootTrustDocument {
    pub schema: String,
    pub configuration_key_id: String,
    pub configuration_public_key_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerMapping {
    pub issuer: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub opaque_owner_ref: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceProofKeyTrust {
    pub opaque_owner_ref: String,
    pub device_id: String,
    pub device_proof_key_ref: String,
    pub public_key_hex: String,
    pub custody: String,
    pub custody_executable: String,
    pub custody_executable_sha256: String,
    pub custody_credential_id: String,
    pub custody_expected_revision: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementProjectionTrust {
    pub issuer: String,
    pub audience: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub opaque_account_ref: String,
    pub current_device_ref: String,
    pub minimum_subject_revocation_epoch: u64,
    pub minimum_service_revocation_epoch: u64,
    pub minimum_device_revocation_epoch: u64,
    pub minimum_session_revocation_epoch: u64,
    pub device_posture_state: String,
    pub minimum_device_posture_revision: u64,
    pub device_proof_key_ref: String,
    pub minimum_snapshot_revision: u64,
    pub key_id: String,
    pub public_key_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteAuthorityRoute {
    pub schema: String,
    pub binding_sha256: String,
    pub address: String,
    pub server_name: String,
    pub audience: String,
    pub device_id: String,
    pub endpoint_deployment_id: String,
    pub authority_deployment_id: String,
    pub client_certificate_path: String,
    pub client_certificate_sha256: String,
    pub client_private_key_path: String,
    pub client_private_key_sha256: String,
    pub server_trust_anchor_path: String,
    pub server_trust_anchor_sha256: String,
    pub server_certificate_sha256: String,
    pub request_key_id: String,
    pub request_public_key_hex: String,
    pub request_signing_key_path: String,
    pub request_signing_key_sha256: String,
    pub response_key_id: String,
    pub response_public_key_hex: String,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaAuthorizationRoute {
    pub schema: String,
    pub executable: String,
    pub executable_sha256: String,
    pub config_path: String,
    pub config_sha256: String,
    pub response_key_id: String,
    pub response_public_key_hex: String,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfigDocument {
    pub schema: String,
    pub deployment_role: String,
    pub endpoint_deployment_id: String,
    pub configuration_generation: u64,
    pub authority_route: RemoteAuthorityRoute,
    pub identity_authority_route: RemoteAuthorityRoute,
    pub pa_authorization_route: PaAuthorizationRoute,
    pub management_projection_trust: ManagementProjectionTrust,
    pub authority_response_key_id: String,
    pub authority_response_public_key_hex: String,
    pub minimum_identity_config_generation: u64,
    pub identity_finalization_authority_id: String,
    pub revocation_approval_authority_ref: String,
    pub identity_issuer: String,
    pub identity_audience: String,
    pub identity_key_id: String,
    pub identity_public_key_hex: String,
    pub current_status_key_id: String,
    pub current_status_public_key_hex: String,
    pub user_verification_key_id: String,
    pub user_verification_public_key_hex: String,
    pub user_verification_credential_id: String,
    pub user_verification_account_binding_sha256: String,
    pub session_sender_key_id: String,
    pub session_sender_key_fingerprint: String,
    pub session_sender_public_key_hex: String,
    pub session_sender_private_key_path: String,
    pub session_sender_private_key_sha256: String,
    pub recovery_approval_key_id: String,
    pub recovery_approval_key_fingerprint: String,
    pub recovery_approval_public_key_hex: String,
    pub recovery_approval_private_key_path: String,
    pub recovery_approval_private_key_sha256: String,
    pub revocation_execution_reservation_key_id: String,
    pub revocation_execution_reservation_public_key_hex: String,
    pub minimum_reservation_config_generation: u64,
    pub endpoint_state_directory: String,
    pub endpoint_anchor_directory: String,
    pub owner_mappings: Vec<OwnerMapping>,
    pub device_proof_keys: Vec<DeviceProofKeyTrust>,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub configuration_key_id: String,
    pub signature: String,
}

#[derive(Clone)]
pub struct VerifiedConfig(pub(crate) AgentConfigDocument);

pub use crate::config_route::authority_route_binding_sha256;
pub use crate::config_verify::verify_config;
