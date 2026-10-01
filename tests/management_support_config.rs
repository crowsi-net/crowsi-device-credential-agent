use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::management_support_route::{identity_route, route};

pub fn value(root: &Path, projection_key: &SigningKey) -> Value {
    let key = |byte: u8| {
        hex::encode(
            SigningKey::from_bytes(&[byte; 32])
                .verifying_key()
                .to_bytes(),
        )
    };
    let owner = "psa_owner_0000000000000001";
    let sender_public = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
    let recovery_public = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
    json!({
        "schema":"crowsi://device-credential-agent/config/v6",
        "deployment_role":"managed-device-endpoint",
        "endpoint_deployment_id":"endpoint-a","configuration_generation":1,
        "authority_route":route(),"identity_authority_route":identity_route(),
        "pa_authorization_route":{
            "schema":"crowsi://device-credential-agent/pa-authorization-route/v1",
            "executable":"/usr/libexec/crowsi-pa-key-agent",
            "executable_sha256":format!("sha256:{}","d".repeat(64)),
            "config_path":"/etc/crowsi/pa-operation-authorize-once.json",
            "config_sha256":format!("sha256:{}","e".repeat(64)),
            "response_key_id":"pa-response-key","response_public_key_hex":"aa".repeat(32),
            "timeout_ms":3000},
        "management_projection_trust":{
            "issuer":"crowsi-credential-authority","audience":"endpoint-a",
            "service_id":"service-a","pairwise_subject":"psu_pairwise-a",
            "opaque_account_ref":owner,"current_device_ref":"device-a",
            "minimum_subject_revocation_epoch":1,"minimum_service_revocation_epoch":1,
            "minimum_device_revocation_epoch":1,"minimum_session_revocation_epoch":1,
            "device_posture_state":"compliant","minimum_device_posture_revision":1,
            "device_proof_key_ref":"device-proof:sha256:device-a","minimum_snapshot_revision":1,
            "key_id":"management-key",
            "public_key_hex":hex::encode(projection_key.verifying_key().to_bytes())},
        "authority_response_key_id":"authority-response-key",
        "authority_response_public_key_hex":key(3),
        "minimum_identity_config_generation":1,
        "identity_finalization_authority_id":"identity-authority",
        "revocation_approval_authority_ref":"independent-authority-c",
        "identity_issuer":"ihat-authority","identity_audience":"crowsi-management",
        "identity_key_id":"identity-key","identity_public_key_hex":key(4),
        "current_status_key_id":"status-key","current_status_public_key_hex":key(5),
        "user_verification_key_id":"uv-key","user_verification_public_key_hex":key(6),
        "user_verification_credential_id":"webauthn-credential-a",
        "user_verification_account_binding_sha256":"1a".repeat(32),
        "session_sender_key_id":"session-sender-key",
        "session_sender_key_fingerprint":hex::encode(Sha256::digest(sender_public)),
        "session_sender_public_key_hex":hex::encode(sender_public),
        "session_sender_private_key_path":"/etc/crowsi/session-sender.json",
        "session_sender_private_key_sha256":format!("sha256:{}","f".repeat(64)),
        "recovery_approval_key_id":"recovery-approval-key",
        "recovery_approval_key_fingerprint":hex::encode(Sha256::digest(recovery_public)),
        "recovery_approval_public_key_hex":hex::encode(recovery_public),
        "recovery_approval_private_key_path":root.join("recovery-approval/key.json"),
        "recovery_approval_private_key_sha256":"sha256:".to_owned()+&"0".repeat(64),
        "revocation_execution_reservation_key_id":"revocation-reservation-key",
        "revocation_execution_reservation_public_key_hex":key(9),
        "minimum_reservation_config_generation":1,
        "endpoint_state_directory":root.join("state"),
        "endpoint_anchor_directory":root.join("anchor"),
        "owner_mappings":[{"issuer":"ihat-authority","service_id":"service-a",
            "pairwise_subject":"psu_pairwise-a","opaque_owner_ref":owner}],
        "device_proof_keys":[{"opaque_owner_ref":owner,"device_id":"device-a",
            "device_proof_key_ref":"device-proof:sha256:device-a","public_key_hex":"bb".repeat(32),
            "custody":"hardware-nonexportable","custody_executable":"/usr/libexec/crowsi-custody",
            "custody_executable_sha256":format!("sha256:{}","12".repeat(32)),
            "custody_credential_id":"credential-a","custody_expected_revision":format!("rev1:{}","2".repeat(64))}],
        "issued_at_epoch_s":super::management_support::NOW-1,
        "expires_at_epoch_s":super::management_support::NOW+3600,
        "configuration_key_id":"config-key","signature":""
    })
}
