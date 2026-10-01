use crowsi_credential_authority_contracts::*;
use crowsi_device_credential_agent::AgentError;

use crate::{management_support::NOW, reconcile_support as support};

#[test]
fn reconcile_retries_only_durable_current_lookup_and_central_bytes() {
    let (fixture, request, wire, prepared, operation) =
        support::prepare("reconcile-retry", NOW + 200);
    let core = fixture.core();
    fixture.fail_current_once();
    assert_eq!(
        core.handle(&wire, NOW),
        Err(AgentError::AuthorityUnavailable)
    );
    assert!(core.handle(&wire, NOW).is_err());
    support::lookup(&fixture, operation.clone(), prepared);
    assert!(core.handle(&wire, NOW).is_err());
    fixture.respond(&request, 6, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: support::response(&operation),
        };
    });
    let first = core.handle(&wire, NOW).expect("reconciled receipt");
    assert_eq!(first, core.handle(&wire, NOW).expect("exact retry"));
    let current = fixture.current_requests();
    assert_eq!(current.len(), 2);
    assert_eq!(current[0], current[1]);
    let lookups: Vec<_> = fixture
        .requests()
        .into_iter()
        .filter(|wire| decode_endpoint_prepared_lookup_request_strict(wire).is_ok())
        .collect();
    assert_eq!(lookups.len(), 2);
    assert_eq!(lookups[0], lookups[1]);
    let central = support::envelopes(&fixture);
    assert_eq!(central.len(), 2);
    assert_eq!(central[0], central[1]);
}

#[test]
fn expired_prepared_is_eligible_only_through_fresh_signed_reconcile_lookup() {
    let (fixture, request, wire, prepared, operation) = support::prepare("reconcile-expired", NOW);
    assert!(fixture.core().handle(&wire, NOW).is_err());
    support::lookup(&fixture, operation.clone(), prepared.clone());
    assert!(fixture.core().handle(&wire, NOW).is_err());
    let envelope = decode_endpoint_management_envelope_strict(
        support::envelopes(&fixture).last().expect("envelope"),
    )
    .expect("strict envelope");
    let EndpointManagementEvidenceV2::Reconcile { prepared: sent, .. } = envelope.evidence else {
        panic!("reconcile evidence")
    };
    assert_eq!(sent, prepared);
    assert_eq!(sent.expires_at_epoch_s, NOW);
    fixture.respond(&request, 6, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: support::response(&operation),
        };
    });
    fixture
        .core()
        .handle(&wire, NOW)
        .expect("historic prepared");
}

#[test]
fn reconcile_projection_is_exact_unknown_receipt() {
    for case in 0..6 {
        let (fixture, request, wire, operation) =
            support::reach_central(&format!("reconcile-projection-{case}"));
        fixture.respond(&request, 6, |value| {
            let mut response = support::response(&operation);
            match case {
                0 => response.state = ManagementOperationState::Completed,
                1 => response.state_revision += 1,
                2 => response.reconcile_digest = Some("55".repeat(32)),
                3 => response.actor.role = RequiredActorRole::NoActor,
                4 => response.reason = None,
                _ => mutate_scope(&mut response),
            }
            value.body = ManagementProjectionBodyV2::Operation {
                operation: response,
            };
        });
        assert_eq!(
            fixture.core().handle(&wire, NOW),
            Err(AgentError::AuthorityResponseInvalid),
            "case {case}"
        );
    }
}

#[test]
fn completed_reconcile_refreshes_same_envelope_after_projection_ttl() {
    let (fixture, request, wire, operation) = support::reach_central("reconcile-refresh");
    fixture.respond(&request, 6, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: support::response(&operation),
        };
    });
    let core = fixture.core();
    core.handle(&wire, NOW).expect("initial receipt");
    let before = support::envelopes(&fixture);
    fixture.respond(&request, 9, |value| {
        value.issued_at_epoch_s = NOW + 31;
        value.expires_at_epoch_s = NOW + 61;
        value.body = ManagementProjectionBodyV2::Operation {
            operation: support::response(&operation),
        };
    });
    core.handle(&wire, NOW + 31).expect("historic refresh");
    let after = support::envelopes(&fixture);
    assert_eq!(after.len(), before.len() + 1);
    assert_eq!(after.last(), before.last());
    fixture.respond(&request, 10, |value| {
        value.issued_at_epoch_s = NOW + 301;
        value.expires_at_epoch_s = NOW + 331;
        value.body = ManagementProjectionBodyV2::Operation {
            operation: support::response(&operation),
        };
    });
    core.handle(&wire, NOW + 301)
        .expect("long historic refresh");
    let long = support::envelopes(&fixture);
    assert_eq!(long.len(), before.len() + 2);
    assert_eq!(long.last(), before.last());
    assert_eq!(fixture.current_requests().len(), 1);
}

fn mutate_scope(value: &mut ManagementOperationV2) {
    let ManagementOperationScopeV2::DeviceTransfer {
        credential_refs, ..
    } = &mut value.scope
    else {
        panic!("transfer scope")
    };
    credential_refs.push("substituted".into());
}
