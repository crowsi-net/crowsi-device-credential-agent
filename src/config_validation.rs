use std::path::Path;

use crate::{
    AgentError,
    config::{AgentConfigDocument, RootTrustDocument},
    validation,
};

pub(crate) fn validate(
    value: &AgentConfigDocument,
    trust: &RootTrustDocument,
    now_epoch_s: u64,
) -> Result<(), AgentError> {
    if value.schema != "crowsi://device-credential-agent/config/v6"
        || trust.schema != "crowsi://device-credential-agent/root-trust/v1"
        || value.deployment_role != "managed-device-endpoint"
        || !validation::id(&value.endpoint_deployment_id, 128)
        || value.configuration_generation == 0
        || value.configuration_key_id != trust.configuration_key_id
        || now_epoch_s < value.issued_at_epoch_s
        || now_epoch_s >= value.expires_at_epoch_s
        || value
            .expires_at_epoch_s
            .saturating_sub(value.issued_at_epoch_s)
            > 31_536_000
        || !validation::id(&value.identity_issuer, 512)
        || !validation::id(&value.identity_audience, 128)
        || !validation::id(&value.identity_key_id, 128)
        || !validation::id(&value.current_status_key_id, 128)
        || !validation::id(&value.user_verification_key_id, 128)
        || !validation::base64url(&value.user_verification_credential_id, 128)
        || !validation::hex_key(&value.user_verification_account_binding_sha256)
        || !validation::id(&value.session_sender_key_id, 128)
        || !validation::hex_key(&value.session_sender_key_fingerprint)
        || !validation::id(&value.recovery_approval_key_id, 128)
        || !validation::hex_key(&value.recovery_approval_key_fingerprint)
        || !validation::id(&value.authority_response_key_id, 128)
        || value.minimum_identity_config_generation == 0
        || !validation::id(&value.identity_finalization_authority_id, 128)
        || !validation::id(&value.revocation_approval_authority_ref, 128)
        || !validation::id(&value.configuration_key_id, 128)
        || !validation::id(&trust.configuration_key_id, 128)
        || value.identity_key_id == value.current_status_key_id
        || value.identity_public_key_hex == value.current_status_public_key_hex
        || !validation::hex_key(&value.identity_public_key_hex)
        || !validation::hex_key(&value.current_status_public_key_hex)
        || !validation::hex_key(&value.user_verification_public_key_hex)
        || !validation::hex_key(&value.session_sender_public_key_hex)
        || !crate::config_validation_roles::session_sender_fingerprint(value)
        || !validation::hex_key(&value.recovery_approval_public_key_hex)
        || !crate::config_validation_roles::recovery_approval_fingerprint(value)
        || !validation::id(&value.revocation_execution_reservation_key_id, 128)
        || !validation::hex_key(&value.revocation_execution_reservation_public_key_hex)
        || value.minimum_reservation_config_generation == 0
        || !Path::new(&value.session_sender_private_key_path).is_absolute()
        || !validation::digest(&value.session_sender_private_key_sha256)
        || !Path::new(&value.recovery_approval_private_key_path).is_absolute()
        || !validation::digest(&value.recovery_approval_private_key_sha256)
        || !validation::hex_key(&value.authority_response_public_key_hex)
        || !validation::hex_key(&trust.configuration_public_key_hex)
        || !state_paths(value)
        || !crate::config_validation_aliases::distinct(value)
        || !crate::config_validation_roles::distinct(value, trust)
        || !crate::config_validation_routes::remote(value)
        || !crate::config_validation_routes::pa(value)
        || !crate::config_validation_routes::management(value)
    {
        return Err(AgentError::ConfigInvalid);
    }
    crate::config_mappings::validate(value)
}

fn state_paths(value: &AgentConfigDocument) -> bool {
    let state = Path::new(&value.endpoint_state_directory);
    let anchor = Path::new(&value.endpoint_anchor_directory);
    state.is_absolute()
        && anchor.is_absolute()
        && state != anchor
        && !state.starts_with(anchor)
        && !anchor.starts_with(state)
}
