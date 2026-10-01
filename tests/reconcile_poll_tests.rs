use crowsi_credential_authority_contracts::*;

use crate::{cancel_support, management_support::NOW, reconcile_support as support};

#[test]
fn completed_poll_does_not_block_a_new_request_for_the_next_revision() {
    let (fixture, first_request, first_wire, operation) =
        support::reach_central("reconcile-poll-1");
    let next = support::response(&operation);
    fixture.respond(&first_request, 6, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: next.clone(),
        };
    });
    fixture.core().handle(&first_wire, NOW).expect("first poll");
    let second_request = support::request("reconcile-poll-2", &next);
    let second_wire = serde_json::to_vec(&second_request).expect("second poll");
    assert!(fixture.core().handle(&second_wire, NOW).is_err());
    let lookup = support::lookup_request(&fixture.requests());
    let prepared = cancel_support::prepared(NOW + 200);
    fixture.respond_lookup(
        cancel_support::lookup(&lookup, next.clone(), prepared),
        |_| {},
    );
    assert!(fixture.core().handle(&second_wire, NOW).is_err());
    fixture.respond(&second_request, 7, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: support::response(&next),
        };
    });
    fixture
        .core()
        .handle(&second_wire, NOW)
        .expect("next revision poll");
    fixture
        .core()
        .handle(&first_wire, NOW)
        .expect("first exact retry remains available");
}
