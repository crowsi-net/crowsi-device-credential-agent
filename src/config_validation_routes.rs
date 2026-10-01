use std::path::Path;

use crate::{config::AgentConfigDocument, validation};

pub(crate) fn management(value: &AgentConfigDocument) -> bool {
    let trust = &value.management_projection_trust;
    validation::id(&trust.issuer, 256)
        && validation::id(&trust.audience, 256)
        && trust.audience == value.endpoint_deployment_id
        && validation::id(&trust.service_id, 128)
        && validation::id(&trust.pairwise_subject, 128)
        && validation::opaque_owner(&trust.opaque_account_ref)
        && validation::id(&trust.current_device_ref, 128)
        && trust.current_device_ref == value.authority_route.device_id
        && trust.minimum_subject_revocation_epoch > 0
        && trust.minimum_service_revocation_epoch > 0
        && trust.minimum_device_revocation_epoch > 0
        && trust.minimum_session_revocation_epoch > 0
        && trust.device_posture_state == "compliant"
        && trust.minimum_device_posture_revision > 0
        && validation::id(&trust.device_proof_key_ref, 240)
        && trust.minimum_snapshot_revision > 0
        && validation::id(&trust.key_id, 128)
        && validation::hex_key(&trust.public_key_hex)
        && value.owner_mappings.iter().any(|mapping| {
            mapping.issuer == value.identity_issuer
                && mapping.service_id == trust.service_id
                && mapping.pairwise_subject == trust.pairwise_subject
                && mapping.opaque_owner_ref == trust.opaque_account_ref
        })
}

pub(crate) fn remote(value: &AgentConfigDocument) -> bool {
    route(&value.authority_route)
        && route(&value.identity_authority_route)
        && value.endpoint_deployment_id == value.authority_route.endpoint_deployment_id
        && value.endpoint_deployment_id == value.identity_authority_route.endpoint_deployment_id
        && value.identity_authority_route.device_id == value.authority_route.device_id
        && value.identity_authority_route.authority_deployment_id
            != value.authority_route.authority_deployment_id
}

fn route(route: &crate::config::RemoteAuthorityRoute) -> bool {
    route.schema == "crowsi://authority-transport/endpoint-route/v1"
        && validation::digest(&route.binding_sha256)
        && validation::id(&route.address, 256)
        && route.address.contains(':')
        && validation::id(&route.server_name, 253)
        && validation::id(&route.audience, 256)
        && validation::id(&route.device_id, 128)
        && validation::id(&route.endpoint_deployment_id, 128)
        && validation::id(&route.authority_deployment_id, 128)
        && route.endpoint_deployment_id != route.authority_deployment_id
        && validation::id(&route.request_key_id, 128)
        && validation::hex_key(&route.request_public_key_hex)
        && validation::id(&route.response_key_id, 128)
        && validation::hex_key(&route.response_public_key_hex)
        && validation::digest(&route.server_certificate_sha256)
        && (100..=30_000).contains(&route.timeout_ms)
        && [
            &route.client_certificate_path,
            &route.client_private_key_path,
            &route.server_trust_anchor_path,
            &route.request_signing_key_path,
        ]
        .iter()
        .all(|item| Path::new(item).is_absolute())
        && [
            &route.client_certificate_sha256,
            &route.client_private_key_sha256,
            &route.server_trust_anchor_sha256,
            &route.request_signing_key_sha256,
        ]
        .iter()
        .all(|item| validation::digest(item))
        && crate::config::authority_route_binding_sha256(route)
            .is_ok_and(|binding| binding == route.binding_sha256)
}

pub(crate) fn pa(value: &AgentConfigDocument) -> bool {
    let route = &value.pa_authorization_route;
    route.schema == "crowsi://device-credential-agent/pa-authorization-route/v1"
        && Path::new(&route.executable).is_absolute()
        && Path::new(&route.config_path).is_absolute()
        && validation::digest(&route.executable_sha256)
        && validation::digest(&route.config_sha256)
        && validation::id(&route.response_key_id, 128)
        && validation::hex_key(&route.response_public_key_hex)
        && (100..=30_000).contains(&route.timeout_ms)
}
