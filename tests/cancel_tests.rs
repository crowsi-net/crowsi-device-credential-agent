use crowsi_credential_authority_contracts::*;
use crowsi_device_credential_agent::AgentError;

use crate::{
    cancel_support as support,
    management_support::{Fixture, NOW},
};

#[test]
fn cancel_retries_only_persisted_current_lookup_and_central_bytes() {
    let fixture = Fixture::new();
    let core = fixture.core();
    let prepared = support::prepared(NOW + 200);
    let operation = support::operation(&prepared);
    let request = support::request("cancel-crash-retry", &operation);
    let wire = serde_json::to_vec(&request).expect("cancel request");
    fixture.fail_current_once();
    assert_eq!(
        core.handle(&wire, NOW),
        Err(AgentError::AuthorityUnavailable)
    );
    assert_eq!(
        core.handle(&wire, NOW),
        Err(AgentError::AuthorityResponseInvalid)
    );
    let lookup_request = support::lookup_request(&fixture.requests());
    fixture.respond_lookup(
        support::lookup(&lookup_request, operation.clone(), prepared),
        |_| {},
    );
    assert_eq!(
        core.handle(&wire, NOW),
        Err(AgentError::AuthorityResponseInvalid)
    );
    fixture.respond(&request, 3, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: support::cancelled(&operation),
        };
    });
    let first = core.handle(&wire, NOW).expect("unknown exact retry");
    let second = core.handle(&wire, NOW).expect("stored cancel receipt");
    assert_eq!(first, second);
    let current = fixture.current_requests();
    assert_eq!(current.len(), 2);
    assert_eq!(current[0], current[1]);
    let requests = fixture.requests();
    let lookup: Vec<_> = requests
        .iter()
        .filter(|wire| decode_endpoint_prepared_lookup_request_strict(wire).is_ok())
        .collect();
    assert_eq!(lookup.len(), 2);
    assert_eq!(lookup[0], lookup[1]);
    let central: Vec<_> = requests
        .iter()
        .filter(|wire| decode_endpoint_management_envelope_strict(wire).is_ok())
        .collect();
    assert_eq!(central.len(), 3);
    assert!(central.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn signed_lookup_substitution_never_reaches_cancel_route() {
    for case in 0..4 {
        let fixture = Fixture::new();
        let core = fixture.core();
        let prepared = support::prepared(NOW + 200);
        let operation = support::operation(&prepared);
        let request = support::request(&format!("cancel-lookup-case-{case}"), &operation);
        let wire = serde_json::to_vec(&request).expect("request");
        assert!(core.handle(&wire, NOW).is_err());
        let lookup_request = support::lookup_request(&fixture.requests());
        fixture.respond_lookup(
            support::lookup(&lookup_request, operation, prepared),
            |value| match case {
                0 => value.actor_session_ref = format!("sref_{}", "b".repeat(64)),
                1 => value.operation.state = ManagementOperationState::Completed,
                2 => value.operation.state_revision += 1,
                _ => value.prepared.source_session_ref = format!("sref_{}", "c".repeat(64)),
            },
        );
        assert_eq!(
            core.handle(&wire, NOW),
            Err(AgentError::AuthorityResponseInvalid)
        );
        assert!(
            fixture
                .requests()
                .iter()
                .all(|wire| { decode_endpoint_management_envelope_strict(wire).is_err() })
        );
    }
}

#[test]
fn signed_cancelled_projection_is_exact_not_just_terminal() {
    for case in 0..5 {
        let (fixture, request, wire, operation) = unknown(&format!("cancel-projection-{case}"));
        fixture.respond(&request, 3, |value| {
            let mut cancelled = support::cancelled(&operation);
            match case {
                0 => cancelled.state = ManagementOperationState::Completed,
                1 => cancelled.state_revision += 1,
                2 => cancelled.actor.role = RequiredActorRole::SourceDevice,
                3 => cancelled.reason = None,
                _ => mutate_scope(&mut cancelled),
            }
            value.body = ManagementProjectionBodyV2::Operation {
                operation: cancelled,
            };
        });
        assert_eq!(
            fixture.core().handle(&wire, NOW),
            Err(AgentError::AuthorityResponseInvalid),
            "case {case}"
        );
    }
}

fn unknown(id: &str) -> (Fixture, ManagementRequestV2, Vec<u8>, ManagementOperationV2) {
    let fixture = Fixture::new();
    let prepared = support::prepared(NOW + 200);
    let operation = support::operation(&prepared);
    let request = support::request(id, &operation);
    let wire = serde_json::to_vec(&request).expect("request");
    assert!(fixture.core().handle(&wire, NOW).is_err());
    let lookup_request = support::lookup_request(&fixture.requests());
    fixture.respond_lookup(
        support::lookup(&lookup_request, operation.clone(), prepared),
        |_| {},
    );
    assert!(fixture.core().handle(&wire, NOW).is_err());
    (fixture, request, wire, operation)
}

fn mutate_scope(value: &mut ManagementOperationV2) {
    let ManagementOperationScopeV2::DeviceTransfer {
        target_device_ref, ..
    } = &mut value.scope
    else {
        panic!("transfer")
    };
    *target_device_ref = "device-c".into();
}
