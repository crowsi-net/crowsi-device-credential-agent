use crowsi_credential_authority_contracts::{
    MANAGEMENT_REQUEST_SCHEMA, ManagementCommandV2, ManagementRequestV2,
};
use crowsi_device_credential_agent::AgentError;

use crate::{
    management_support::{Fixture, NOW},
    management_support_request::request,
};

#[test]
fn signing_roles_reject_duplicate_ids_or_public_keys() {
    for duplicate in [
        "id",
        "key",
        "recovery-id",
        "recovery-key",
        "reservation-id",
        "reservation-key",
    ] {
        let fixture = Fixture::with_config_change(|value| match duplicate {
            "id" => {
                value["management_projection_trust"]["key_id"] = value["identity_key_id"].clone();
            }
            "key" => {
                value["management_projection_trust"]["public_key_hex"] =
                    value["identity_public_key_hex"].clone();
            }
            "recovery-id" => {
                value["recovery_approval_key_id"] = value["session_sender_key_id"].clone();
            }
            "recovery-key" => {
                value["recovery_approval_public_key_hex"] =
                    value["session_sender_public_key_hex"].clone();
            }
            "reservation-id" => {
                value["revocation_execution_reservation_key_id"] =
                    value["authority_response_key_id"].clone();
            }
            _ => {
                value["revocation_execution_reservation_public_key_hex"] =
                    value["authority_response_public_key_hex"].clone();
            }
        });
        assert!(matches!(fixture.try_core(), Err(AgentError::ConfigInvalid)));
    }
}

#[test]
fn signed_paths_and_artifacts_reject_cross_role_aliases() {
    for case in 0..6 {
        let fixture = Fixture::with_config_change(|value| match case {
            0 => {
                value["identity_authority_route"]["client_private_key_path"] =
                    value["authority_route"]["client_private_key_path"].clone();
            }
            1 => {
                value["identity_authority_route"]["client_private_key_sha256"] =
                    value["authority_route"]["client_private_key_sha256"].clone();
            }
            2 => {
                value["session_sender_private_key_path"] = value["endpoint_state_directory"]
                    .as_str()
                    .expect("state")
                    .to_owned()
                    .into();
            }
            3 => {
                value["recovery_approval_private_key_path"] =
                    value["session_sender_private_key_path"].clone();
            }
            4 => {
                value["recovery_approval_private_key_sha256"] =
                    value["session_sender_private_key_sha256"].clone();
            }
            _ => {
                value["recovery_approval_private_key_path"] =
                    value["endpoint_anchor_directory"].clone();
            }
        });
        assert!(matches!(fixture.try_core(), Err(AgentError::ConfigInvalid)));
    }
}

#[test]
fn signed_endpoint_state_binding_rejects_downgrade_alias_and_route_drift() {
    for case in 0..4 {
        let fixture = Fixture::with_config_change(|value| match case {
            0 => value["configuration_generation"] = 0.into(),
            1 => value["endpoint_deployment_id"] = "different-endpoint".into(),
            2 => value["endpoint_anchor_directory"] = value["endpoint_state_directory"].clone(),
            _ => {
                let state = value["endpoint_state_directory"]
                    .as_str()
                    .expect("state path");
                value["endpoint_anchor_directory"] = format!("{state}/nested").into();
            }
        });
        assert!(
            matches!(fixture.try_core(), Err(AgentError::ConfigInvalid)),
            "case {case}"
        );
    }
}

#[test]
fn persistent_lock_file_left_by_a_killed_process_does_not_block_restart() {
    let fixture = Fixture::new();
    fixture.leave_unlocked_guard_file();
    let request = request("request-after-restart");
    fixture.respond(&request, 1, |_| {});
    fixture
        .core()
        .handle(&serde_json::to_vec(&request).expect("wire"), NOW)
        .expect("persistent flock file is reusable after process death");
}

#[test]
fn stale_central_receipt_for_reused_id_fails_exact_command_correlation() {
    let fixture = Fixture::new();
    let old = request("bounded-reuse");
    fixture.respond(&old, 1, |_| {});
    fixture
        .core()
        .handle(&serde_json::to_vec(&old).expect("old wire"), NOW)
        .expect("old response");
    let new = ManagementRequestV2 {
        schema: MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: old.request_id,
        command: ManagementCommandV2::PendingList {
            service_id: "service-a".into(),
        },
    };
    assert_eq!(
        fixture
            .core()
            .handle(&serde_json::to_vec(&new).expect("new wire"), NOW),
        Err(AgentError::AuthorityResponseInvalid)
    );
}

include!("management_v2_recovery_key_security_tests.rs");
