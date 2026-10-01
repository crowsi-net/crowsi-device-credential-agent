use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementCommandV2, ManagementIntentV2, ManagementProjectionV2,
    ManagementRequestV2, SignedAuthorityExchangeV1, endpoint_operation_digest,
    endpoint_operation_id, management_command_digest,
};
use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AUTHORITY_RESPONSE_SCHEMA, AuthorityCommand, AuthorityRequestV1,
    AuthorityResponseV1, AuthorityResult, BeginFreshUvCommand, FreshUvRequestOptions,
    ResponseOutcome, command_digest,
};

#[path = "source_options_verify_test_identity.rs"]
mod identity;
#[path = "source_options_verify_test_projection.rs"]
mod projection;

pub(super) const NOW: u64 = 100;

pub(super) struct Fixture {
    pub browser: ManagementRequestV2,
    pub identity: SignedAuthorityExchangeV1,
    pub prepared: EndpointPreparedOperationV2,
    pub begin: SignedAuthorityExchangeV1,
    pub projection: ManagementProjectionV2,
}

pub(super) fn fixture() -> Fixture {
    let identity = identity::exchange();
    let browser = ManagementRequestV2 {
        schema: crowsi_credential_authority_contracts::MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: "browser-request".into(),
        command: ManagementCommandV2::SourceOptions {
            intent: ManagementIntentV2::DeviceTransfer {
                service_id: "service".into(),
                target_device_ref: "device-b".into(),
                credential_refs: vec!["credential-a".into()],
                expected_snapshot_revision: 7,
                nonce: "browser-nonce".into(),
            },
        },
    };
    let ManagementCommandV2::SourceOptions { intent } = &browser.command else {
        unreachable!()
    };
    let mut prepared = EndpointPreparedOperationV2 {
        operation_id: String::new(),
        origin_command_digest_sha256: management_command_digest(&browser).expect("browser digest"),
        source_device_ref: "device-a".into(),
        source_session_ref: "session-a".into(),
        pairwise_subject: "psu_subject".into(),
        opaque_owner_ref: "owner-a".into(),
        source_identity_nonce: "identity-nonce".into(),
        nonce: "operation-nonce".into(),
        issued_at_epoch_s: NOW,
        expires_at_epoch_s: NOW + 300,
        intent: intent.clone(),
        revocation: None,
    };
    prepared.operation_id = endpoint_operation_id(&prepared).expect("operation id");
    let begin_request = begin_request(&prepared);
    let begin = SignedAuthorityExchangeV1 {
        response: response(
            &begin_request,
            AuthorityResult::FreshUvBegun(options(&begin_request)),
            NOW,
            NOW + 30,
        ),
        request: begin_request,
    };
    let projection = projection::value(&prepared, &begin);
    Fixture {
        browser,
        identity,
        prepared,
        begin,
        projection,
    }
}

fn begin_request(prepared: &EndpointPreparedOperationV2) -> AuthorityRequestV1 {
    AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: "begin-request".into(),
        command: AuthorityCommand::BeginFreshUserVerification(BeginFreshUvCommand {
            command_id: "begin-command".into(),
            credential_id: "credential-a".into(),
            identity_nonce: prepared.source_identity_nonce.clone(),
            source_device_id: prepared.source_device_ref.clone(),
            service_id: "service".into(),
            pairwise_subject: prepared.pairwise_subject.clone(),
            session_ref: prepared.source_session_ref.clone(),
            operation_digest_sha256: endpoint_operation_digest(prepared).expect("operation digest"),
            subject_epoch: 1,
            service_epoch: 1,
            device_epoch: 1,
            session_epoch: 1,
        }),
        evidence: Vec::new(),
    }
}

fn options(request: &AuthorityRequestV1) -> FreshUvRequestOptions {
    FreshUvRequestOptions {
        attempt_id: "attempt-a".into(),
        challenge: "challenge_a".into(),
        rp_id: "example.test".into(),
        origin: "https://example.test".into(),
        credential_id: "credential-a".into(),
        timeout_ms: 120_000,
        expires_at_epoch_s: NOW + 120,
        command_binding_sha256: command_digest(request).expect("begin digest"),
    }
}

fn response(
    request: &AuthorityRequestV1,
    result: AuthorityResult,
    issued: u64,
    expires: u64,
) -> AuthorityResponseV1 {
    AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: request.request_id.clone(),
        command_type: request.command.type_name().into(),
        command_digest: command_digest(request).expect("response digest"),
        config_generation: 2,
        issued_at_epoch_s: issued,
        expires_at_epoch_s: expires,
        outcome: ResponseOutcome::Committed { result },
        key_id: "response-key".into(),
        signature: "22".repeat(64),
    }
}
