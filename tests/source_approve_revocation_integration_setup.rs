fn source_context(fixture: &Fixture) -> SourceContext {
    let core = Box::new(fixture.core());
    let snapshot = management_support_request::request("revocation-snapshot");
    fixture.respond(&snapshot, 1, |value| {
        value.body = ManagementProjectionBodyV2::Snapshot {
            snapshot: revocation::snapshot(),
        };
    });
    core.handle(&serde_json::to_vec(&snapshot).expect("snapshot wire"), NOW)
        .expect("cache snapshot");

    let options = revocation::request("revocation-source-options");
    let options_wire = serde_json::to_vec(&options).expect("source options wire");
    assert_eq!(
        core.handle(&options_wire, NOW),
        Err(AgentError::AuthorityResponseInvalid)
    );
    let central = fixture.requests();
    let (prepared, begin) = source::source_evidence(central.last().expect("source envelope"));
    fixture.respond(&options, 2, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: revocation::operation(&prepared, &begin),
        };
    });
    core.handle(&options_wire, NOW)
        .expect("complete source options");
    SourceContext {
        core,
        prepared: Box::new(prepared),
        begin: Box::new(begin),
    }
}
