struct Context {
    core: Box<Core>,
    prepared: Box<EndpointPreparedOperationV2>,
    approval: Box<ManagementRequestV2>,
    approval_wire: Vec<u8>,
    preaccepted: Box<ManagementOperationV2>,
}

fn setup(kind: support::Kind) -> (Fixture, Context) {
    let fixture = Fixture::new();
    let core = Box::new(fixture.core());
    let snapshot = management_support_request::request(&format!("self-{}-snapshot", kind.label()));
    fixture.respond(&snapshot, 1, |value| {
        value.body = ManagementProjectionBodyV2::Snapshot {
            snapshot: support::snapshot(),
        };
    });
    core.handle(&serde_json::to_vec(&snapshot).expect("snapshot wire"), NOW)
        .expect("cache snapshot");

    let options = support::request(kind, &format!("self-{}-options", kind.label()));
    let options_wire = serde_json::to_vec(&options).expect("options wire");
    assert_eq!(
        core.handle(&options_wire, NOW),
        Err(AgentError::AuthorityResponseInvalid)
    );
    let central = fixture.requests();
    let (prepared, begin) =
        support::source_evidence(central.last().expect("source options envelope"));
    fixture.respond(&options, 2, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: support::operation(kind, &prepared, &begin),
        };
    });
    core.handle(&options_wire, NOW)
        .expect("complete source options");
    let approval = Box::new(approve::request(
        &format!("self-{}-approve", kind.label()),
        &prepared,
        &begin,
    ));
    let approval_wire = serde_json::to_vec(approval.as_ref()).expect("approval wire");
    let preaccepted = Box::new(support::preaccepted(kind, &prepared, &begin));
    (
        fixture,
        Context {
            core,
            prepared: Box::new(prepared),
            approval,
            approval_wire,
            preaccepted,
        },
    )
}

fn respond_preaccepted(fixture: &Fixture, context: &Context) {
    fixture.respond(context.approval.as_ref(), 3, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: context.preaccepted.as_ref().clone(),
        };
    });
}

fn first_finalize_request(fixture: &Fixture) -> EndpointRevocationFinalizeRequestV1 {
    let requests = fixture.finalize_requests();
    support::finalize_request(requests.first().expect("finalize request"))
}
