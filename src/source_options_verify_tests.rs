use super::{INVALID, projection, strict, validate_begin};
use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, EndpointManagementEvidenceV2, ManagementOperationV2,
    ManagementProjectionBodyV2,
};
use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityResult, ResponseOutcome, command_digest,
};
#[path = "source_options_verify_test_support.rs"]
mod support;
#[test]
fn begin_is_causal_empty_and_bound_to_configured_credential_and_prepared_operation() {
    let value = support::fixture();
    assert_eq!(
        validate_begin(
            "credential-a",
            &value.identity,
            &value.prepared,
            &value.begin,
            support::NOW,
        ),
        Ok(())
    );
    let mut nonempty = value.begin.clone();
    nonempty.request.evidence = value.identity.request.evidence.clone();
    recorrelate(&mut nonempty);
    assert_invalid(&value, &nonempty);
    let mut wrong_credential = value.begin.clone();
    let AuthorityCommand::BeginFreshUserVerification(command) =
        &mut wrong_credential.request.command
    else {
        unreachable!()
    };
    command.credential_id = "credential-b".into();
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(options),
    } = &mut wrong_credential.response.outcome
    else {
        unreachable!()
    };
    options.credential_id = "credential-b".into();
    recorrelate(&mut wrong_credential);
    assert_invalid(&value, &wrong_credential);

    let mut rollback = value.begin.clone();
    rollback.response.config_generation = value.identity.response.config_generation - 1;
    assert_invalid(&value, &rollback);

    let mut early = value.begin.clone();
    early.response.issued_at_epoch_s = support::NOW - 1;
    assert_invalid(&value, &early);

    let mut overlong = value.begin.clone();
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(options),
    } = &mut overlong.response.outcome
    else {
        unreachable!()
    };
    options.expires_at_epoch_s = value.prepared.expires_at_epoch_s + 1;
    assert_invalid(&value, &overlong);
}

#[test]
fn full_envelope_and_phase_specific_projection_must_be_exact() {
    let value = support::fixture();
    let envelope = EndpointManagementEnvelopeV2 {
        schema: crowsi_credential_authority_contracts::ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: value.browser.clone(),
        evidence: EndpointManagementEvidenceV2::SourceOptions {
            identity_exchange: value.identity.clone(),
            prepared: value.prepared.clone(),
            uv_options: value.begin.clone(),
        },
    };
    assert_eq!(strict(envelope.clone()), Ok(envelope));
    assert_eq!(
        projection(&value.prepared, &value.begin, 7, &value.projection),
        Ok(())
    );
    let mut advanced_head = value.projection.clone();
    advanced_head.snapshot_revision = 12;
    assert_eq!(
        projection(&value.prepared, &value.begin, 7, &advanced_head),
        Ok(())
    );

    let mut wrong_revision = value.projection.clone();
    wrong_revision.snapshot_revision = 7;
    assert_eq!(
        projection(&value.prepared, &value.begin, 7, &wrong_revision),
        Err(INVALID)
    );

    let mut wrong_state = value.projection.clone();
    operation(&mut wrong_state).state_revision = 2;
    assert_eq!(
        projection(&value.prepared, &value.begin, 7, &wrong_state),
        Err(INVALID)
    );

    let mut substituted_options = value.projection.clone();
    operation(&mut substituted_options)
        .webauthn_options
        .as_mut()
        .expect("options")
        .challenge = "substituted".into();
    assert_eq!(
        projection(&value.prepared, &value.begin, 7, &substituted_options),
        Err(INVALID)
    );
}

fn assert_invalid(
    value: &support::Fixture,
    begin: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
) {
    assert_eq!(
        validate_begin(
            "credential-a",
            &value.identity,
            &value.prepared,
            begin,
            support::NOW,
        ),
        Err(INVALID)
    );
}

fn recorrelate(value: &mut crowsi_credential_authority_contracts::SignedAuthorityExchangeV1) {
    let digest = command_digest(&value.request).expect("digest");
    value.response.command_digest.clone_from(&digest);
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(options),
    } = &mut value.response.outcome
    else {
        unreachable!()
    };
    options.command_binding_sha256 = digest;
}

fn operation(
    value: &mut crowsi_credential_authority_contracts::ManagementProjectionV2,
) -> &mut ManagementOperationV2 {
    let ManagementProjectionBodyV2::Operation { operation } = &mut value.body else {
        unreachable!()
    };
    operation
}
