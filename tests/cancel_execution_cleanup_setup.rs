fn setup() -> (
    Fixture,
    Box<Core>,
    EndpointPreparedOperationV2,
    ManagementOperationV2,
    ManagementRequestV2,
    Vec<u8>,
) {
    let fixture = Fixture::new();
    let core = Box::new(fixture.core());
    let snapshot = management_support_request::request("cancel-reserved-snapshot");
    fixture.respond(&snapshot, 1, |value| {
        value.body = ManagementProjectionBodyV2::Snapshot {
            snapshot: source::snapshot(),
        };
    });
    core.handle(&serde_json::to_vec(&snapshot).expect("snapshot"), NOW)
        .expect("cache snapshot");
    let options = source::request(source::Kind::Device, "cancel-reserved-options");
    let options_wire = serde_json::to_vec(&options).expect("options");
    assert!(core.handle(&options_wire, NOW).is_err());
    let (prepared, begin) =
        source::source_evidence(fixture.requests().last().expect("source options envelope"));
    let operation = source::operation(source::Kind::Device, &prepared, &begin);
    fixture.respond(&options, 2, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: operation.clone(),
        };
    });
    core.handle(&options_wire, NOW).expect("source options");
    let approval = approve::request("cancel-reserved-approve", &prepared, &begin);
    let approval_wire = serde_json::to_vec(&approval).expect("approval");
    let preaccepted = source::preaccepted(source::Kind::Device, &prepared, &begin);
    fixture.respond(&approval, 3, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: preaccepted.clone(),
        };
    });
    fixture.fail_reservation_once();
    assert_eq!(
        core.handle(&approval_wire, NOW),
        Err(AgentError::AuthorityUnavailable)
    );
    (
        fixture,
        core,
        prepared,
        preaccepted,
        approval,
        approval_wire,
    )
}
