use crowsi_credential_authority_contracts::*;
use crowsi_device_credential_agent::AgentError;

use crate::{
    cancel_support,
    management_support::{Fixture, NOW},
    reconcile_support as support,
};

#[test]
fn fifth_reconcile_poll_retires_oldest_complete_without_blocking_operation() {
    let fixture = Fixture::new();
    let prepared = cancel_support::prepared(NOW + 299);
    let mut operation = support::unknown(&prepared, 5);
    let mut completed = Vec::new();
    for index in 0..5 {
        let request = support::request(&format!("reconcile-capacity-{index}"), &operation);
        let wire = serde_json::to_vec(&request).expect("reconcile wire");
        assert!(fixture.core().handle(&wire, NOW).is_err());
        let lookup = support::lookup_request(&fixture.requests());
        fixture.respond_lookup(
            cancel_support::lookup(&lookup, operation.clone(), prepared.clone()),
            |_| {},
        );
        assert!(fixture.core().handle(&wire, NOW).is_err());
        operation = support::response(&operation);
        fixture.respond(&request, operation.state_revision, |value| {
            value.body = ManagementProjectionBodyV2::Operation {
                operation: operation.clone(),
            };
        });
        fixture
            .core()
            .handle(&wire, NOW + index)
            .expect("reconcile poll");
        completed.push(wire);
    }
    let calls = fixture.requests().len();
    assert_eq!(
        fixture.core().handle(&completed[0], NOW + 5),
        Err(AgentError::OperationReplay)
    );
    assert_eq!(fixture.requests().len(), calls);
    fixture
        .core()
        .handle(&completed[4], NOW + 5)
        .expect("fifth exact retry");
}
