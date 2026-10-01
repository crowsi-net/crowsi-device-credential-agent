use crowsi_credential_authority_contracts::*;
use ihat_identity_assertion_contracts::{AuthorityResult, ResponseOutcome};

pub fn request(
    id: &str,
    prepared: &EndpointPreparedOperationV2,
    begin: &SignedAuthorityExchangeV1,
) -> ManagementRequestV2 {
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(options),
    } = &begin.response.outcome
    else {
        panic!("fresh options")
    };
    ManagementRequestV2 {
        schema: MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: id.into(),
        command: ManagementCommandV2::SourceApprove {
            operation_id: prepared.operation_id.clone(),
            expected_state_revision: 1,
            attempt_id: options.attempt_id.clone(),
            assertion: WebAuthnAssertionV2 {
                credential_id: options.credential_id.clone(),
                client_data_json_base64url: "Y2xpZW50".into(),
                authenticator_data_base64url: "YXV0aA".into(),
                signature_der_base64url: "c2ln".into(),
            },
        },
    }
}

pub fn operation(
    prepared: &EndpointPreparedOperationV2,
    begin: &SignedAuthorityExchangeV1,
) -> ManagementOperationV2 {
    let mut value = crate::source_options_support::operation(prepared, begin);
    let ManagementIntentV2::DeviceTransfer {
        target_device_ref, ..
    } = &prepared.intent
    else {
        panic!("transfer")
    };
    value.state = ManagementOperationState::AwaitingTarget;
    value.state_revision = 2;
    value.webauthn_options = None;
    value.actor = ActorRequirementV2 {
        role: RequiredActorRole::TargetDevice,
        required_actor_device_ref: Some(target_device_ref.clone()),
        required_approval_authority_ref: None,
        excluded_actor_device_refs: vec![prepared.source_device_ref.clone()],
    };
    value
}
