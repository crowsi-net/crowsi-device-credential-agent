use crate::{
    cancel_support as support,
    management_support::{Fixture, NOW},
};
use crowsi_credential_authority_contracts::*;

#[test]
fn terminal_cancel_receipts_do_not_consume_active_cancel_slots() {
    let fixture = Fixture::new();
    for index in 0..33 {
        complete(&fixture, index);
    }
}

fn complete(fixture: &Fixture, index: usize) {
    let mut prepared = support::prepared(NOW + 200);
    prepared.nonce = format!("cancel-capacity-{index}");
    prepared.operation_id = endpoint_operation_id(&prepared).expect("operation id");
    let operation = support::operation(&prepared);
    let request = support::request(&format!("cancel-capacity-{index}"), &operation);
    let wire = serde_json::to_vec(&request).expect("cancel wire");
    assert!(fixture.core().handle(&wire, NOW).is_err());
    let lookup = latest_lookup(&fixture.requests());
    fixture.respond_lookup(
        support::lookup(&lookup, operation.clone(), prepared),
        |_| {},
    );
    assert!(fixture.core().handle(&wire, NOW).is_err());
    fixture.respond(&request, 10 + index as u64, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: support::cancelled(&operation),
        };
    });
    let core = fixture.core();
    core.handle(&wire, NOW).expect("cancel complete");
    assert_eq!(
        core.cancel_retirement_state(&request.request_id, &operation.operation_id)
            .expect("retirement state"),
        (false, false, true)
    );
    assert!(core.operation_journal_bytes().expect("journal bytes") <= 131_072);
}

fn latest_lookup(wires: &[Vec<u8>]) -> EndpointPreparedLookupRequestV1 {
    wires
        .iter()
        .rev()
        .find_map(|wire| decode_endpoint_prepared_lookup_request_strict(wire).ok())
        .expect("cancel lookup")
}
