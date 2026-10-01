use std::{collections::BTreeSet, path::Path};

use crate::{AgentError, config::AgentConfigDocument, validation};

pub(crate) fn validate(value: &AgentConfigDocument) -> Result<(), AgentError> {
    if value.device_proof_keys.len() != 1 {
        return Err(AgentError::ConfigInvalid);
    }
    let mut tuples = BTreeSet::new();
    let mut owners = BTreeSet::new();
    let mut devices = BTreeSet::new();
    for mapping in &value.owner_mappings {
        let key = (
            &mapping.issuer,
            &mapping.service_id,
            &mapping.pairwise_subject,
        );
        if mapping.issuer != value.identity_issuer
            || !validation::id(&mapping.service_id, 128)
            || !mapping.pairwise_subject.starts_with("psu_")
            || !validation::id(&mapping.pairwise_subject, 128)
            || !validation::opaque_owner(&mapping.opaque_owner_ref)
            || !tuples.insert(key)
            || !owners.insert(&mapping.opaque_owner_ref)
        {
            return Err(AgentError::ConfigInvalid);
        }
    }
    for key in &value.device_proof_keys {
        let unique = (&key.opaque_owner_ref, &key.device_id);
        if !value
            .owner_mappings
            .iter()
            .any(|item| item.opaque_owner_ref == key.opaque_owner_ref)
            || !validation::id(&key.device_id, 128)
            || key.device_id != value.authority_route.device_id
            || key.device_id != value.identity_authority_route.device_id
            || key.opaque_owner_ref != value.management_projection_trust.opaque_account_ref
            || key.device_proof_key_ref != value.management_projection_trust.device_proof_key_ref
            || !validation::id(&key.device_proof_key_ref, 240)
            || !validation::hex_key(&key.public_key_hex)
            || !Path::new(&key.custody_executable).is_absolute()
            || !validation::digest(&key.custody_executable_sha256)
            || !validation::id(&key.custody_credential_id, 128)
            || !valid_revision(&key.custody_expected_revision)
            || !devices.insert(unique)
            || !matches!(
                key.custody.as_str(),
                "hardware-nonexportable" | "software-nonexportable"
            )
        {
            return Err(AgentError::ConfigInvalid);
        }
    }
    let key = &value.device_proof_keys[0];
    let role_ids = [
        &value.configuration_key_id,
        &value.identity_key_id,
        &value.current_status_key_id,
        &value.user_verification_key_id,
        &value.authority_response_key_id,
        &value.management_projection_trust.key_id,
        &value.authority_route.request_key_id,
        &value.authority_route.response_key_id,
        &value.identity_authority_route.request_key_id,
        &value.identity_authority_route.response_key_id,
        &value.pa_authorization_route.response_key_id,
    ];
    let role_keys = [
        &value.identity_public_key_hex,
        &value.current_status_public_key_hex,
        &value.user_verification_public_key_hex,
        &value.authority_response_public_key_hex,
        &value.management_projection_trust.public_key_hex,
        &value.authority_route.request_public_key_hex,
        &value.authority_route.response_public_key_hex,
        &value.identity_authority_route.request_public_key_hex,
        &value.identity_authority_route.response_public_key_hex,
        &value.pa_authorization_route.response_public_key_hex,
    ];
    if role_ids.contains(&&key.device_proof_key_ref) || role_keys.contains(&&key.public_key_hex) {
        return Err(AgentError::ConfigInvalid);
    }
    Ok(())
}

fn valid_revision(value: &str) -> bool {
    value.len() == 69
        && value.starts_with("rev1:")
        && value[5..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
