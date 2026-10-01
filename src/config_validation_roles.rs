use std::collections::BTreeSet;

use crate::config::{AgentConfigDocument, RootTrustDocument};

pub(crate) fn session_sender_fingerprint(value: &AgentConfigDocument) -> bool {
    let Ok(public) = hex::decode(&value.session_sender_public_key_hex) else {
        return false;
    };
    value.session_sender_key_fingerprint == crate::crypto::key_fingerprint(&public)
}

pub(crate) fn recovery_approval_fingerprint(value: &AgentConfigDocument) -> bool {
    let Ok(public) = hex::decode(&value.recovery_approval_public_key_hex) else {
        return false;
    };
    value.recovery_approval_key_fingerprint == crate::crypto::key_fingerprint(&public)
}

pub(crate) fn distinct(value: &AgentConfigDocument, trust: &RootTrustDocument) -> bool {
    let ids = [
        &trust.configuration_key_id,
        &value.identity_key_id,
        &value.current_status_key_id,
        &value.user_verification_key_id,
        &value.authority_response_key_id,
        &value.session_sender_key_id,
        &value.recovery_approval_key_id,
        &value.revocation_execution_reservation_key_id,
        &value.management_projection_trust.key_id,
        &value.authority_route.request_key_id,
        &value.authority_route.response_key_id,
        &value.identity_authority_route.request_key_id,
        &value.identity_authority_route.response_key_id,
        &value.pa_authorization_route.response_key_id,
    ];
    let keys = [
        &trust.configuration_public_key_hex,
        &value.identity_public_key_hex,
        &value.current_status_public_key_hex,
        &value.user_verification_public_key_hex,
        &value.session_sender_public_key_hex,
        &value.recovery_approval_public_key_hex,
        &value.revocation_execution_reservation_public_key_hex,
        &value.authority_response_public_key_hex,
        &value.management_projection_trust.public_key_hex,
        &value.authority_route.request_public_key_hex,
        &value.authority_route.response_public_key_hex,
        &value.identity_authority_route.request_public_key_hex,
        &value.identity_authority_route.response_public_key_hex,
        &value.pa_authorization_route.response_public_key_hex,
    ];
    let mut distinct_ids = ids
        .iter()
        .map(|item| item.as_str())
        .collect::<BTreeSet<_>>();
    let mut distinct_keys = keys
        .iter()
        .map(|item| item.as_str())
        .collect::<BTreeSet<_>>();
    ids.len() == distinct_ids.len()
        && keys.len() == distinct_keys.len()
        && value.device_proof_keys.iter().all(|item| {
            distinct_ids.insert(item.device_proof_key_ref.as_str())
                && distinct_keys.insert(item.public_key_hex.as_str())
        })
}
